import hashlib
import hmac
import os
import os.path as op

from Cryptodome.Cipher import AES

SQLITE_FILE_HEADER = b"SQLite format 3\x00"  # SQLite文件头

KEY_SIZE = 32
DEFAULT_PAGESIZE = 4096
DEFAULT_ITER = 64000


def decrypt(key: str, db_path: str, out_path: str):
    """
    通过密钥解密数据库
    :param key: 密钥 64位16进制字符串
    :param db_path:  待解密的数据库路径(必须是文件)
    :param out_path:  解密后的数据库输出路径(必须是文件)
    :return:
    """
    assert len(key) == 64, f"invalid key with length != 64: '{key}'"
    assert op.isfile(db_path), f"not a file: '{db_path}'"

    password = bytes.fromhex(key)
    with open(db_path, "rb") as file:
        bs = file.read()

    salt = bs[:16]
    assert len(salt) == 16, f"invalid db file: '{db_path}'"

    b_key = hashlib.pbkdf2_hmac("sha1", password, salt, DEFAULT_ITER, KEY_SIZE)
    first = bs[16:DEFAULT_PAGESIZE]

    mac_salt = bytes(i ^ 58 for i in salt)
    mac_key = hashlib.pbkdf2_hmac("sha1", b_key, mac_salt, 2, KEY_SIZE)
    hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
    hash_mac.update(b'\x01\x00\x00\x00')

    assert hash_mac.digest() == first[-32:-12], "Key Error"

    new_bs = [first]
    new_bs.extend(
        bs[i : i + DEFAULT_PAGESIZE]
        for i in range(DEFAULT_PAGESIZE, len(bs), DEFAULT_PAGESIZE)
    )

    with open(out_path, "wb") as fp:
        fp.write(SQLITE_FILE_HEADER)

        for b in new_bs:
            t = AES.new(b_key, AES.MODE_CBC, b[-48:-32])
            decrypted = t.decrypt(b[:-48])
            fp.write(decrypted)
            fp.write(b[-48:])


def batch_decrypt(key: str, db_path: str | list[str], out_path: str):
    process_list = []

    if isinstance(db_path, str):
        if not op.exists(db_path):
            return

        if op.isfile(db_path):
            inpath = db_path
            outpath = op.join(out_path, 'de_' + op.basename(db_path))
            process_list.append((key, inpath, outpath))

        elif op.isdir(db_path):
            for root, dirs, files in os.walk(db_path):
                for file in files:
                    inpath = op.join(root, file)
                    rel = op.relpath(root, db_path)
                    outpath = op.join(out_path, rel, 'de_' + file)

                    if not op.exists(op.dirname(outpath)):
                        os.makedirs(op.dirname(outpath))
                    process_list.append((key, inpath, outpath))
        else:
            return

    elif isinstance(db_path, list):
        rt_path = op.commonprefix(db_path)
        if not op.exists(rt_path):
            rt_path = op.dirname(rt_path)

        for inpath in db_path:
            if not op.exists(inpath):
                continue

            inpath = op.normpath(inpath)
            rel = op.relpath(op.dirname(inpath), rt_path)
            outpath = op.join(out_path, rel, 'de_' + op.basename(inpath))
            if not op.exists(op.dirname(outpath)):
                os.makedirs(op.dirname(outpath))
            process_list.append((key, inpath, outpath))

    for k, d, o in process_list:
        try:
            decrypt(k, d, o)
        except AssertionError:
            pass

    # 删除空文件夹
    for root, dirs, _ in os.walk(out_path, topdown=False):
        for dir in dirs:
            tmp = op.join(root, dir)
            if not os.listdir(tmp):
                os.rmdir(tmp)
