import logging
import os
import os.path as op
import sys
from pprint import pprint

import click

from .bias import get_bias_by_info, update_bias_data
from .crypto import batch_decrypt
from .info import get_wx_db, read_info

logging.basicConfig(
    format='[%(levelname)s] %(message)s',
    level=logging.DEBUG,
    stream=sys.stdout,
)
logger = logging.getLogger(__file__)


class OrderedGroup(click.Group):
    def list_commands(self, _):
        return self.commands.keys()


@click.group(cls=OrderedGroup)
def cli():
    """微信消息导出工具"""


@cli.command(name='bias')
@click.option("--name", help="微信昵称", required=True)
@click.option("--account", help="微信账号", required=True)
@click.option("--phone", help="手机号", required=True)
@click.option("--key", help="(可选)密钥")
@click.option("--db-path", help="(可选)已登录账号的微信文件夹路径")
@click.option("--bdp", help="(可选)微信版本偏移文件路径（更新该文件）")
def cmd_get_bias(
    name: str,
    account: str,
    phone: str,
    key: str | None,
    db_path: str | None,
    bdp: str | None,
):
    """获取微信基址偏移"""
    rdata = get_bias_by_info(
        name.encode(), account.encode(), phone.encode(), key, db_path
    )
    pprint(rdata)
    if bdp is not None:
        update_bias_data(bdp, rdata)


@cli.command(name='info')
@click.option("--bdp", help="(可选)微信版本偏移文件路径")
def cmd_get_info(bdp: str | None):
    """获取微信信息"""
    info_list = read_info(bdp)
    if info_list is not None:
        for info in info_list:
            pprint(info)


DEFAULT_OUTPUT = 'output'


@cli.command(name='dump')
@click.option('-o', '--output', help='path to decrypt db files')
def cmd_dump(output: str | None):
    """导出微信消息"""
    if output is None:
        output = DEFAULT_OUTPUT
    if not op.exists(output):
        os.mkdir(output)

    info_list = read_info()
    if info_list is None:
        print('not found. nothing to do, exit.')
        return

    for info in info_list:
        logger.debug(f'{info=}')
        if info.key is None:
            print(f'not found key: {info.name}')
            continue

        wx_db_path = get_wx_db('all', None, info.wxid)
        # logger.debug(f'{wx_db_path=}')
        if wx_db_path is None:
            print(f'not found db path: {info.name}')
            continue

        wx_db_path_list = [op.join(k, vv) for k, v in wx_db_path.items() for vv in v]
        # 过滤掉无需解密的数据库
        wx_db_path_list = [
            i for i in wx_db_path_list if "Backup.db" not in i and "xInfo.db" not in i
        ]

        # logger.debug(f'{wx_db_path_list=}')
        if len(wx_db_path_list) == 0:
            print(f'not found db path: {info.name}')
            continue

        if info.wxid is None:
            output_path = output
        else:
            output_path = op.join(output, info.wxid)
            if not op.exists(output_path):
                os.mkdir(output_path)

        batch_decrypt(info.key, wx_db_path_list, output_path)
