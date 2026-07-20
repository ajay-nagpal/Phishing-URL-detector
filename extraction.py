import os
import csv
import pandas as pd

from typing import Any
from concurrent.futures import ThreadPoolExecutor

from basic_features import extract_basic_features
from dmn_features import extract_advanced_features
from internet_features import extract_internet_features

# Input and output file names.
INPUT_FILE = "Phishing_URL_Dataset.csv"
OUTPUT_FILE = "Phishing_Features.csv"
CHECKPOINT_FILE = "checkpoint.txt"
FAILED_FILE = "failed_urls.csv"

# Number of worker threads.
# Multiple URLs are processed in parallel to
# reduce the total execution time.
MAX_WORKERS = 10

# Number of rows written to disk at once.
# Writing in batches is much faster than
# writing every row individually.
BATCH_SIZE = 100


# Load checkpoint.
# If extraction stopped previously, resume from
# the last successfully written row.
last_processed = -1

if os.path.exists(CHECKPOINT_FILE):
    try:
        with open(CHECKPOINT_FILE, "r") as f:
            last_processed = int(f.read().strip())
    except Exception:
        last_processed = -1


# Read only the required dataset columns.
# Keeping only URL and label reduces memory usage.
df = pd.read_csv(
    INPUT_FILE,
    usecols=["URL", "label"]
)

if df.empty:
    raise ValueError("Input dataset is empty.")

# Determine whether output file already exists.
# Existing files are appended to instead of
# overwriting previous results.
file_exists = (
    os.path.exists(OUTPUT_FILE)
    and os.path.getsize(OUTPUT_FILE) > 0
)

# Open output CSV.
# Append mode resumes extraction after crashes.
# Write mode creates a new dataset.
csv_file = open(
    OUTPUT_FILE,
    "a" if file_exists else "w",
    newline="",
    encoding="utf-8"
)

# Open failed URL log.
# Any unexpected extraction errors are stored
# here for later inspection.
failed_file = open(
    FAILED_FILE,
    "a",
    newline="",
    encoding="utf-8"
)

failed_writer = csv.writer(failed_file)

# Write header only once.
if failed_file.tell() == 0:
    failed_writer.writerow([
        "original_index",
        "URL",
        "Error"
    ])

# Create CSV header.
# The feature extraction functions return a
# dictionary. The dictionary keys become the
# output CSV column names.
if not file_exists:

    header = None

    # Try URLs until one succeeds.
    # Some malformed URLs may fail extraction.
    for url in df["URL"]:
        try:
            header = {"URL": url}

            # Add feature names from every module.
            header.update(extract_basic_features(url))

            header.update(extract_advanced_features(url))

            header.update(extract_internet_features(url))

            break

        except Exception as e:
            
            print(f"Skipping header URL: {e}")

    if header is None:
        raise RuntimeError("Unable to build CSV header.")

    # Include target label column.
    header["label"] = 0

    writer = csv.DictWriter(
        csv_file,
        fieldnames=header.keys()
    )

    writer.writeheader()

else:

    # Existing CSV already contains the header.
    # Read it so future rows follow the exact
    # same column order.
    with open(OUTPUT_FILE,"r",
        newline="",encoding="utf-8") as f:

        reader = csv.reader(f)
        fieldnames = next(reader)

    writer = csv.DictWriter(csv_file,fieldnames=fieldnames)

# Worker function.
# Extracts all features for one URL.
# Returns:
# (row index, feature dictionary, error message)
def process_row(original_index, row):
    try:
        # Start with the original URL.
        features: dict[str, Any] = {"URL": row.URL}

        # Merge features from each extraction module.
        features.update(extract_basic_features(row.URL))

        features.update(extract_advanced_features(row.URL))

        features.update(extract_internet_features(row.URL))

        # Preserve original dataset label.
        features["label"] = row.label

        return (original_index,features,None)

    except Exception as e:

        # If extraction fails completely,
        # create an empty row so the output
        # dataset keeps the correct structure.
        failed = {
            column: None
            for column in writer.fieldnames
        }

        failed["URL"] = row.URL
        failed["label"] = row.label

        return (original_index,failed,str(e))

# ThreadPoolExecutor.map() accepts one argument.
# This wrapper unpacks the tuple into process_row().
def worker(args):
    return process_row(*args)

# Prepare rows for processing.
# Skip rows that were already processed during
# a previous execution.
rows = []

for index, row in enumerate(df.itertuples(index=False)):

    if index <= last_processed:
        continue

    rows.append((index,row))

# Batch of extracted rows waiting to be written.
batch = []

# Tracks the latest completed row.
current_index = last_processed

# Parallel feature extraction.
# Multiple worker threads process different URLs
# simultaneously to improve performance.
try:

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        # executor.map() returns results in the
        # same order as the input rows.
        for original_index, features, error in executor.map(
            worker,rows):

            current_index = original_index

            # Record extraction failures.
            if error is not None:
                print(f"Error at row {original_index}: {error}")

                failed_writer.writerow([original_index,
                    features["URL"],error])

                failed_file.flush()

            # Store extracted features in memory.
            batch.append(features)

            # Write a batch to disk once it reaches
            # the configured batch size.
            if len(batch) >= BATCH_SIZE:

                writer.writerows(batch)
                csv_file.flush()
                batch.clear()

                # Save checkpoint so extraction can
                # resume from this point if interrupted.
                with open(CHECKPOINT_FILE, "w") as cp:
                    cp.write(str(current_index))

                print(f"Written {current_index + 1} rows")

    # Write any remaining rows after processing
    # finishes.
    if batch:

        writer.writerows(batch)
        csv_file.flush()

        with open(CHECKPOINT_FILE, "w") as cp:
            cp.write(str(current_index))

        print(f"Written {current_index + 1} rows")

# Allow Ctrl+C without losing completed work.
except KeyboardInterrupt:

    print("\nStopping safely...")

    if batch:

        writer.writerows(batch)
        csv_file.flush()

        with open(CHECKPOINT_FILE, "w") as cp:
            cp.write(str(current_index))

    print("Checkpoint saved.")

    raise

# close open files.
# This ensures all buffered data is written.
finally:

    csv_file.close()
    failed_file.close()

print("Feature extraction completed successfully.")