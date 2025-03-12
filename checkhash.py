import os
import hashlib

def calculate_hashes(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes for a given file."""
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        # Read the file in chunks to avoid using too much memory
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)

    return hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest()

def check_hashes_in_folder(folder_path):
    """Check hashes of all files in the specified folder."""
    if not os.path.isdir(folder_path):
        print(f"The path {folder_path} is not a valid directory.")
        return

    print(f"Calculating hashes for files in: {folder_path}\n")
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            md5_hash, sha1_hash, sha256_hash = calculate_hashes(file_path)
            print(f"File: {file_path}")
            print(f"MD5: {md5_hash}")
            print(f"SHA1: {sha1_hash}")
            print(f"SHA256: {sha256_hash}\n")

if __name__ == "__main__":
    folder_to_check = input("Enter the path of the folder to check: ")
    check_hashes_in_folder(folder_to_check)