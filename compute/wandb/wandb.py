import bittensor as bt
import wandb
import pathlib
import os
import hashlib
import json
from collections import Counter

from dotenv import load_dotenv
from compute.utils.db import ComputeDb
from neurons.Validator.database.pog import retrieve_stats, write_stats
from neurons.Validator.script import get_perf_info
from compute import __version_as_int__

PUBLIC_WANDB_NAME = "opencompute"
PUBLIC_WANDB_ENTITY = "neuralinternet"
NEURALINTERNET_VALIDATOR_RUN = f"{PUBLIC_WANDB_ENTITY}/{PUBLIC_WANDB_NAME}/0djlnjjs"


class ComputeWandb:
    run = None

    def __init__(self, config: bt.config, wallet: bt.wallet, role: str):
        self.config = config.copy()

        keys_to_delete = ["logging", "wallet", "full_path", "axon"]
        for key in keys_to_delete:
            if key in self.config:
                del self.config[key]

        self.wallet = wallet
        self.hotkey = wallet.hotkey.ss58_address
        self.role = os.path.splitext(role)[0]
        self.entity = PUBLIC_WANDB_ENTITY

        # ComputeDB to store run_id
        self.db = ComputeDb()

        # Check wandb API key
        load_dotenv()
        netrc_path = pathlib.Path.home() / ".netrc"
        wandb_api_key = os.getenv("WANDB_API_KEY")

        if not wandb_api_key and not netrc_path.exists():
            raise ValueError("Please log in to wandb using `wandb login` or set the WANDB_API_KEY environment variable.")

        self.api = wandb.Api()
        self.project = self.api.project(PUBLIC_WANDB_NAME, entity=PUBLIC_WANDB_ENTITY)
        self.project_run_id = f"{self.entity}/{self.project.name}"
        self.run_name = f"{self.role}-{self.hotkey}"

        # Try to get an existing run_id for the hotkey
        self.run_id = self.get_run_id(self.hotkey)
        try:
            if self.run_id is None:
                filter_rule = {
                    "$and": [
                        {"config.config.netuid": self.config.netuid},
                        {"display_name": self.run_name},
                    ]
                }
                # Get all runs with the run_name
                runs = self.api.runs(f"{PUBLIC_WANDB_ENTITY}/{PUBLIC_WANDB_NAME}", filters=filter_rule)
                # Get the latest run and init from the found run on wandb
                if len(runs)>=1:
                    latest_run = runs[0]
                    self.run_id = latest_run.id
                    # Store the new run_id in the database
                    self.save_run_id(self.hotkey, self.run_id)
                    # Remove the unused run_id from the database
                    if len(runs) > 1:
                        for run in runs:
                            if run.id != self.run_id and run.state != "running":
                                run.delete(delete_artifacts=(True))
                    wandb.finish()
                # run can't be found on wandb either, so initialize a new run
                elif len(runs)==0:
                    # No existing run_id, so initialize a new run
                    run = wandb.init(project=self.project.name, entity=self.entity, name=self.run_name)
                    self.run_id = run.id
                    # Store the new run_id in the database
                    self.save_run_id(self.hotkey, self.run_id)
                    wandb.finish()

            self.run = wandb.init(project=self.project.name, entity=self.entity, id=self.run_id, resume="allow")
        except Exception as e:
            bt.logging.warning(f"wandb init failed: {e}")

        self.update_config()

    def update_config(self):
        if self.run:
            self.run.name = self.run_name

            update_dict = {
                "hotkey": self.hotkey,
                "role": self.role,
                "config": self.config,
                "version": __version_as_int__,
            }
            self.run.config.update(update_dict, allow_val_change=True)
            # wandb.log({"dummy_metric": 0})

            # Sign the run to ensure it's from the correct hotkey
            self.sign_run()

        else:
            bt.logging.warning(f"wandb init failed, update config not possible.")

    def save_run_id(self, hotkey, run_id):
        cursor = self.db.get_cursor()
        try:
            # Check if the hotkey already exists in the database
            cursor.execute("SELECT run_id FROM wandb_runs WHERE hotkey = ?", (hotkey,))
            result = cursor.fetchone()
            if result is None:
                # If the hotkey does not exist, insert the new run_id
                cursor.execute("INSERT INTO wandb_runs (hotkey, run_id) VALUES (?, ?)", (hotkey, run_id))
                self.db.conn.commit()
            else:
                # If the hotkey exists, log a message and do not update the run_id
                bt.logging.info(f"Hotkey {hotkey} already exists in the wandb. Run ID not updated.")
        except Exception as e:
            self.db.conn.rollback()
            bt.logging.error(f"ComputeDb error: {e}")
        finally:
            cursor.close()

    def get_run_id(self, hotkey):
        cursor = self.db.get_cursor()
        try:
            cursor.execute("SELECT run_id FROM wandb_runs WHERE hotkey = ?", (hotkey,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            bt.logging.error(f"ComputeDb error: {e}")
            return None
        finally:
            cursor.close()

    def update_specs(self):
        """
        You can fake these information. Do it at your own risk.
        The validators will send the number of challenges accordingly to the specifications provided here.
        So if you fake something you'll end with a very degraded score :clown:.
        Also, when your miner is allocated, the allocated user can give back a mark of reliability.
        The smaller reliability is, the faster you'll be dereg.
        """
        if self.run:
            update_dict = {
                "specs": get_perf_info(encrypted=False),
            }
            self.run.config.update(update_dict, allow_val_change=True)

            # Sign the run
            self.sign_run()

            bt.logging.info(f"✅ Hardware details uploaded to Wandb.")
        else:
            bt.logging.warning(f"wandb init failed, update specs not possible.")

    def log_chain_data(self, data):
        if self.run:
            self.run.log(data)
            bt.logging.info(f"✅ Logging chain data to Wandb.")
        else:
            bt.logging.warning(f"wandb init failed, logging not possible.")

    def update_allocated(self, allocated):
        """
        This function update the allocated value on miner side.
        It's useless to fake this information because its only used as public purpose.
        Not used by the validators to calculate your steak :meat:.
        allocated: hotkey of the validator allocating
        """
        if self.run:
            update_dict = {
                "allocated": allocated
            }
            self.run.config.update(update_dict, allow_val_change=True)

            # Sign the run
            self.sign_run()
        else:
            bt.logging.warning(f"wandb init failed, update allocated not possible.")

    def update_stats(self, stats: dict):
        """
        This function updates the challenge stats for all miners on validator side.
        It's useless to alter this information as it's only used for data analysis.
        Not used by the validators to calculate your steak :meat:.
        """
        if self.run:
            self.run.log({"stats": stats})
            bt.logging.info(f"✅ Logging stats to Wandb.")
        else:
            bt.logging.warning(f"wandb init failed, logging stats not possible.")

    def _update_allocated_hotkeys(self, hotkey_list):
        """
        This function updates the allocated hotkeys on the validator side and syncs the allocation with the database.
        """
        self.api.flush()

        # Retrieve current stats from the database
        stats = retrieve_stats(self.db)

        # Update the `allocated` field in stats based on `hotkey_list`
        for uid, data in stats.items():
            hotkey = data.get("hotkey")
            if hotkey in hotkey_list:
                data["allocated"] = True  # Mark as allocated if the hotkey is in the list
            else:
                data["allocated"] = False  # Mark as not allocated if the hotkey is not in the list

        # Write the updated stats back to the database
        write_stats(self.db, stats)

        preview = {uid: {"hotkey": d["hotkey"],
                     "allocated": d["allocated"],
                     "gpu_specs": d["gpu_specs"]}
               for uid, d in stats.items() if 160 <= uid <= 170}          # first 10 UIDs
        bt.logging.debug(f"[DBG wandb-update] stats preview → {preview}")

        # Prepare the update dictionary for the configuration
        update_dict = {
            "allocated_hotkeys": hotkey_list,  # Update allocated hotkeys
            "stats": stats  # Updated stats with allocation status
        }
        self.run.config.update(update_dict, allow_val_change=True)

        # Log the allocated hotkeys for tracking
        self.run.log({"allocated_hotkeys": self.run.config["allocated_hotkeys"]})

        # Sign the run
        self.sign_run()

    def update_allocated_hotkeys(self, hotkey_list, penalized_hotkeys):
        """
        This function updates the allocated hotkeys on the validator side and syncs the allocation with the database,
        then flattens the gpu_specs into gpu_name/num_gpus before pushing to WandB.
        """
        self.api.flush()

        # 1) pull current stats from local DB
        stats = retrieve_stats(self.db)

        # 2) update allocation flag
        for uid, data in stats.items():
            data["allocated"] = data.get("hotkey") in hotkey_list

        # 3) persist back to DB
        write_stats(self.db, stats)

        # 4) flatten gpu_specs for WandB
        flat_stats: dict[int, dict] = {}
        for uid, data in stats.items():
            specs = data.pop("gpu_specs", {}) or {}
            flat_stats[uid] = {
                "uid":               uid,
                "hotkey":            data.get("hotkey"),
                "gpu_name":          specs.get("gpu_name"),
                "gpu_num":          specs.get("num_gpus"),
                "score":             data.get("score"),
                "allocated":         data.get("allocated"),
                "own_score":         data.get("own_score"),
                "reliability_score": data.get("reliability_score"),
                "created_at":        data.get("created_at"),
            }


        # 6) send to WandB
        update_dict = {
            "allocated_hotkeys": hotkey_list,
            "stats":             flat_stats,
            "penalized_hotkeys_checklist": penalized_hotkeys
        }
        self.run.config.update(update_dict, allow_val_change=True)

         # Log the allocated hotkeys for tracking
        self.run.log({"allocated_hotkeys": self.run.config["allocated_hotkeys"]})

        # Sign the run
        self.sign_run()

    def update_penalized_hotkeys_checklist(self, hotkey_list):
        """
        This function updates the penalized hotkeys checklist on validator side.
        It's useless to alter this information as it needs to be signed by a valid validator hotkey.
        """
        self.api.flush()

        # Update the configuration with the new keys
        update_dict = {
                "penalized_hotkeys_checklist": hotkey_list
            }
        self.run.config.update(update_dict, allow_val_change=True)

        # Track penalized hotkeys checklist over time
        self.run.log({"penalized_hotkeys_checklist": self.run.config["penalized_hotkeys_checklist"]})

        # Sign the run
        self.sign_run()

    def update_penalized_hotkeys(self, hotkey_list):
        """
        This function updates the allocated hotkeys on validator side.
        It's useless to alter this information as it needs to be signed by a valid validator hotkey.
        """
        self.api.flush()

        # Update the configuration with the new keys
        update_dict = {
                "penalized_hotkeys": hotkey_list
            }
        self.run.config.update(update_dict, allow_val_change=True)

        # Track allocated hotkeys over time
        self.run.log({"penalized_hotkeys": self.run.config["penalized_hotkeys"]})

        # Sign the run
        self.sign_run()

    def update_miner_port_open(self, is_port_open):
        """
        This function updates the port on miner side.
        It's useless to alter this information as it needs to be signed by a valid miner hotkey.
        """
        if self.run:
            update_dict = {
                "is_port_open": is_port_open,
            }
            self.run.config.update(update_dict, allow_val_change=True)

            # Track is_port_open
            self.run.log({"is_port_open": self.run.config["is_port_open"]})

            # Sign the run
            self.sign_run()

            bt.logging.info(f"✅ Miner's server port uploaded to Wandb.")
        else:
            bt.logging.warning(f"wandb init failed, update port not possible.")

    def get_allocated_hotkeys(self, valid_validator_hotkeys, flag):
        """
        This function gets all allocated hotkeys from all validators.
        Only relevant for validators.
        """
        # Query all runs in the project and Filter runs where the role is 'validator'
        self.api.flush()
        validator_runs = self.api.runs(path=f"{PUBLIC_WANDB_ENTITY}/{PUBLIC_WANDB_NAME}",
                                       filters={"$and": [{"config.role": "validator"},
                                                         {"config.config.netuid": self.config.netuid},
                                                         {"config.allocated_hotkeys": {"$exists": True}},]
                                                })

         # Check if the runs list is empty
        if not validator_runs:
            bt.logging.info("No validator info found in the project opencompute.")
            return []

        # Initialize an empty list to store allocated keys from runs with a valid signature
        allocated_keys_list = []

        # Verify the signature for each validator run
        for run in validator_runs:
            try:
                # Access the run's configuration
                run_config = run.config
                hotkey = run_config.get('hotkey')
                allocated_keys = run_config.get('allocated_hotkeys')

                valid_validator_hotkey = hotkey in valid_validator_hotkeys

                # Allow all validator hotkeys for data retrieval only if flag == false
                if not flag:
                    valid_validator_hotkey = True

                if self.verify_run(run) and allocated_keys and valid_validator_hotkey:
                            allocated_keys_list.extend(allocated_keys)  # Add the keys to the list

            except Exception as e:
                bt.logging.info(f"Run ID: {run.id}, Name: {run.name}, Error: {e}")

        return allocated_keys_list

    def get_stats_allocated(self, valid_validator_hotkeys, flag):
        """
        Aggregates stats from all validator runs on wandb, returning a dict keyed by UID.
        Only includes entries where 'own_score' == True (and optionally 'allocated' == True).
        Then picks one 'dominant' entry per UID and preserves all fields (e.g., allocated).
        """

        # helper: get gpu name/num from either 'gpu_specs' or top-level
        def _gpu_name_num(entry: dict):
            specs = entry.get("gpu_specs") or {}
            name = specs.get("gpu_name")
            num  = specs.get("gpu_num")
            if name is None:
                name = entry.get("gpu_name", "N/A")
            if num is None:
                num = entry.get("gpu_num", 0)
            return name, num

        # 1) fetch all validator runs that have stats
        self.api.flush()
        validator_runs = self.api.runs(
            path=f"{PUBLIC_WANDB_ENTITY}/{PUBLIC_WANDB_NAME}",
            filters={
                "$and": [
                    {"config.role": "validator"},
                    {"config.config.netuid": self.config.netuid},
                    {"config.stats": {"$exists": True}},
                ]
            }
        )
        if not validator_runs:
            bt.logging.info("No validator info found in the project opencompute.")
            return {}

        aggregator: dict[str, list[dict]] = {}

        for run in validator_runs:
            try:
                rc         = run.config
                hotkey     = rc.get("hotkey")
                stats_data = rc.get("stats", {})

                # — guard: if W&B returned stats as a JSON string, parse it —
                if isinstance(stats_data, str):
                    try:
                        stats_data = json.loads(stats_data)
                    except Exception as e:
                        bt.logging.warning(f"Could not parse stats JSON for run {run.id}: {e}")
                        continue

                is_valid_hk = (hotkey in valid_validator_hotkeys) or not flag
                if not (self.verify_run(run) and isinstance(stats_data, dict) and is_valid_hk):
                    continue

                # — collect each UID entry if it meets own_score, score>0, allocated —
                for uid_str, entry in stats_data.items():
                    if entry.get("own_score") and entry.get("score", 0) > 0 and entry.get("allocated"):
                        aggregator.setdefault(uid_str, []).append(entry)
                        gname, gnum = _gpu_name_num(entry)
                        bt.logging.trace(
                            f"Added stats for UID {uid_str} from {hotkey} | "
                            f"GPU: {gname} x {gnum}"
                        )

            except Exception as e:
                bt.logging.info(f"Run ID: {run.id}, Name: {run.name}, Error: {e}")

        # 2) helper to pick the “dominant” entry per UID
        def pick_dominant(valid_entries: list[dict]) -> dict:
            combos = [
                (*_gpu_name_num(d), d["score"])
                for d in valid_entries
            ]
            counts = Counter(combos)
            if not counts:
                return max(valid_entries, key=lambda d: d["score"])
            top_combo, _ = counts.most_common(1)[0]
            # tie-break on highest score
            top_ties = [c for c, ct in counts.items() if ct == counts[top_combo]]
            if len(top_ties) > 1:
                top_combo = max(top_ties, key=lambda t: t[2])
            for d in valid_entries:
                if (*_gpu_name_num(d), d["score"]) == top_combo:
                    d["own_score"] = True
                    return d

        # 3) pick one per UID, convert UID to int
        final: dict[int, dict] = {}
        for uid_str, entries in aggregator.items():
            valid_entries = [e for e in entries if e.get("score", 0) != 0]
            if not valid_entries:
                continue
            chosen = valid_entries[0] if len(valid_entries) == 1 else pick_dominant(valid_entries)
            final[int(uid_str)] = chosen

        return final

    def get_penalized_hotkeys(self, valid_validator_hotkeys, flag):
        """
        This function gets all allocated hotkeys from all validators.
        Only relevant for validators.
        """
        # Query all runs in the project and Filter runs where the role is 'validator'
        self.api.flush()
        validator_runs = self.api.runs(path=f"{PUBLIC_WANDB_ENTITY}/{PUBLIC_WANDB_NAME}",
                                    filters={"$and": [{"config.role": "validator"},
                                                        {"config.config.netuid": self.config.netuid},
                                                        {"config.penalized_hotkeys": {"$exists": True}},]
                                                })

        # Check if the runs list is empty
        if not validator_runs:
            bt.logging.info("No validator info found in the project opencompute.")
            return []

        # Initialize an empty list to store allocated keys from runs with a valid signature
        penalized_keys_list = []

        # Verify the signature for each validator run
        for run in validator_runs:
            try:
                # Access the run's configuration
                run_config = run.config
                hotkey = run_config.get('hotkey')
                penalized_keys = run_config.get('penalized_hotkeys')

                valid_validator_hotkey = hotkey in valid_validator_hotkeys

                # Allow all validator hotkeys for data retrieval only
                if not flag:
                    valid_validator_hotkey = True

                if self.verify_run(run) and penalized_keys and valid_validator_hotkey:
                            penalized_keys_list.extend(penalized_keys)  # Add the keys to the list

            except Exception as e:
                bt.logging.info(f"Run ID: {run.id}, Name: {run.name}, Error: {e}")

        return penalized_keys_list

    def get_penalized_hotkeys_checklist_bak(self, valid_validator_hotkeys, flag):
        """
        This function gets all penalized hotkeys checklist from all validators.
        Only relevant for validators.
        """
        # Query all runs in the project and Filter runs where the role is 'validator'
        self.api.flush()
        valid_validator_hotkeys = ["5GmvyePN9aYErXBBhBnxZKGoGk4LKZApE4NkaSzW62CYCYNA"]
        validator_runs = self.api.runs(path=f"{PUBLIC_WANDB_ENTITY}/{PUBLIC_WANDB_NAME}",
                                       filters={"$and": [{"config.role": "validator"},
                                                         {"config.config.netuid": self.config.netuid},
                                                         {"config.penalized_hotkeys_checklist": {"$exists": True}},
                                                         {"config.hotkey": {"$in": valid_validator_hotkeys}},]
                                                })

         # Check if the runs list is empty
        if not validator_runs:
            bt.logging.info("No validator info found in the project opencompute.")
            return []

        # Initialize an empty list to store penalized hotkeys checklist from runs with a valid signature
        all_penalized_hotkeys_checklist = []

        # Verify the signature for each validator run
        for run in validator_runs:
            try:
                # Access the run's configuration
                run_config = run.config
                hotkey = run_config.get('hotkey')
                penalized_hotkeys_checklist = run_config.get('penalized_hotkeys_checklist')

                valid_validator_hotkey = hotkey in valid_validator_hotkeys

                # Allow all validator hotkeys for data retrieval only
                if not flag:
                    valid_validator_hotkey = True

                if self.verify_run(run) and penalized_hotkeys_checklist and valid_validator_hotkey:
                    all_penalized_hotkeys_checklist.extend(penalized_hotkeys_checklist)  # Add the keys to the list

            except Exception as e:
                bt.logging.info(f"Run ID: {run.id}, Name: {run.name}, Error: {e}")

        return all_penalized_hotkeys_checklist

    def get_miner_specs(self, queryable_uids):
        """
        This function gets all specs from miners.
        Only relevant for validators.
        """
        # Dictionary to store the (hotkey, specs) from wandb runs
        db_specs_dict = {}

        self.api.flush()
        runs = self.api.runs(f"{PUBLIC_WANDB_ENTITY}/{PUBLIC_WANDB_NAME}",
                            filters={"$and": [{"config.role": "miner"},
                                               {"config.config.netuid": self.config.netuid},
                                               {"state": "running"}]
                                    })
        try:
            # Iterate over all runs in the opencompute project
            for index, run in enumerate(runs, start=1):
                # Access the run's configuration
                run_config = run.config
                hotkey = run_config.get('hotkey')
                specs = run_config.get('specs')

                # check the signature
                if self.verify_run(run) and specs:
                    # Add the index and (hotkey, specs) tuple to the db_specs_dict if hotkey is valid
                    valid_hotkeys = [axon.hotkey for axon in queryable_uids.values() if axon.hotkey]
                    if hotkey in valid_hotkeys:
                        db_specs_dict[index] = (hotkey, specs)

        except Exception as e:
            # Handle the exception by logging an error message
            bt.logging.error(f"An error occurred while getting specs from wandb: {e}")

        # Return the db_specs_dict for further use or inspection
        return db_specs_dict

    def sign_run(self):
        # Include the run ID in the data to be signed
        data_to_sign = self.run_id

        # Compute a SHA-256 hash of the data to be signed
        data_hash = hashlib.sha256(data_to_sign.encode()).digest()

        # Sign the hash with the hotkey
        signature = self.wallet.hotkey.sign(data_hash).hex()
        update_dict = {
                "signature": signature
            }
        self.run.config.update(update_dict, allow_val_change=True)
        self.run.log({"dummy_metric": 0})
        self.api.flush()

    def verify_run(self, run):
        # Access the run's configuration
        run_config = run.config

        # Extract hotkey and signature from the run's summary
        hotkey = run_config.get('hotkey')
        signature = run.config.get('signature')  # Assuming signature is stored in summary
        run_id_str = run.id

        # Recreate the data that was signed
        data_to_sign = run_id_str

        # Compute a SHA-256 hash of the data to be signed
        data_hash = hashlib.sha256(data_to_sign.encode()).digest()

        if hotkey and signature:
            try:
                if bt.Keypair(ss58_address=hotkey).verify(data_hash, bytes.fromhex(signature)):
                    return True
                else:
                    bt.logging.info(f"Run ID: {run_id_str}, Name: {run.name}, Failed Signature: The signature is not valid.")
            except Exception as e:
                bt.logging.info(f"Error verifying signature for Run ID: {run_id_str}, Name: {run.name}: {e}")

        return False

    def sync_allocated(self, hotkey):
        """
        This function syncs the allocated status of the miner with the wandb run.
        """
        # Fetch allocated hotkeys
        allocated_hotkeys = self.get_allocated_hotkeys([], False)

        if hotkey in allocated_hotkeys:
            return True
        else:
            return False

    def get_penalized_hotkeys_checklist(self, valid_validator_hotkeys, flag):
        """ This function gets penalized hotkeys checklist from a specific hardcoded validator. """
        # Hardcoded run ID
        run_id = "neuralinternet/opencompute/ckig4h3x"
        # Fetch the specific run by its ID
        self.api.flush()
        run = self.api.run(run_id)
        if not run:
            bt.logging.info(f"No run info found for ID {run_id}.")
            return []
        # Access the run's configuration
        try:
            run_config = run.config
            penalized_hotkeys_checklist = run_config.get('penalized_hotkeys_checklist')
            return penalized_hotkeys_checklist
        except Exception as e:
            bt.logging.info(f"Run ID: {run.id}, Name: {run.name}, Error: {e}")
            return []

    def get_reliability_scores(self) -> dict[int, float]:
        """
        Reads reliability_score per UID from the single authoritative validator run.
        Returns {uid: reliability_score} with values clamped to [0, 1].
        """
        self.api.flush()
        run_path = NEURALINTERNET_VALIDATOR_RUN
        try:
            run = self.api.run(run_path)
            if not run:
                bt.logging.info(f"No run info found for path {run_path}.")
                return {}

            # Refresh to avoid cached/stale config
            try:
                run.reload()
            except Exception as e:
                bt.logging.warning(f"Failed to reload run {getattr(run, 'id', None)}: {e}")

            rc = run.config

            # Verify the signature for authenticity
            if not self.verify_run(run):
                bt.logging.info(f"Signature verification failed for {run_path}.")
                return {}

            stats_data = rc.get("stats", {})

            # Parse if returned as JSON string
            if isinstance(stats_data, str):
                try:
                    stats_data = json.loads(stats_data)
                except Exception as e:
                    bt.logging.info(f"Could not parse stats JSON for run {run.id}: {e}")
                    return {}

            if not isinstance(stats_data, dict):
                return {}

            out: dict[int, float] = {}
            for uid_str, entry in stats_data.items():
                if not isinstance(entry, dict):
                    continue

                # Resolve UID from key or entry["uid"]
                try:
                    uid = int(uid_str)
                except Exception:
                    try:
                        uid = int(entry.get("uid"))
                    except Exception:
                        continue

                r = entry.get("reliability_score")
                if r is None:
                    continue

                try:
                    val = float(r)
                except Exception:
                    continue

                # Drop NaNs and clamp to [0,1]
                if val != val:
                    continue
                if val < 0.0:
                    val = 0.0
                elif val > 1.0:
                    val = 1.0

                out[uid] = val

            return out

        except Exception as e:
            bt.logging.warning(f"Run fetch error for {run_path}: {e}")
            return {}