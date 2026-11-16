#!/bin/bash
set -e
cd "$(dirname "$0")"
mkdir -p raw/zenodo raw/figshare raw/kaggle raw/epvme
C="curl -L -C - --retry 20 --retry-delay 5 --retry-all-errors"

$C -o raw/zenodo/Merged_Dataset.csv "https://zenodo.org/api/records/17314806/files/Merged_Dataset.csv/content"

$C -o raw/figshare/Assassin.csv "https://ndownloader.figshare.com/files/45117799"
$C -o raw/figshare/Ling.csv     "https://ndownloader.figshare.com/files/45117802"
$C -o raw/figshare/Enron.csv    "https://ndownloader.figshare.com/files/45117805"
$C -o raw/figshare/TREC-06.csv  "https://ndownloader.figshare.com/files/45117808"
$C -o raw/figshare/CEAS-08.csv  "https://ndownloader.figshare.com/files/45117811"
$C -o raw/figshare/TREC-07.csv  "https://ndownloader.figshare.com/files/45117814"
$C -o raw/figshare/TREC-05.csv  "https://ndownloader.figshare.com/files/45117817"

$C -o raw/kaggle/phishing.zip "https://www.kaggle.com/api/v1/datasets/download/naserabdullahalam/phishing-email-dataset"
(cd raw/kaggle && unzip -oq phishing.zip)

for i in 1 2 3 4 5 6 7 8; do
  $C -o raw/epvme/EPVME_$i.zip "https://github.com/sunknighteric/EPVME-Dataset/raw/main/EPVME_$i.zip"
  (cd raw/epvme && unzip -oq EPVME_$i.zip)
done

echo "Done. Now run: python3 build_dataset.py"
