#!/bin/sh

directories="mac url"
output_dir="txt"

mkdir -p "$output_dir"

convert_man_to_txt() {
  input_file=$1
  output_file="${output_dir}/$(basename "${input_file%.3}.txt")"
  man "$input_file" | col -b > "$output_file"
  echo "Converted $input_file to $output_file"
}

for dir in $directories; do
  if [ -d "$dir" ]; then
    find "$dir" -type f -name "*.3" | while read -r file; do
      convert_man_to_txt "$file"
    done
  else
    echo "Directory $dir does not exist"
  fi
done
