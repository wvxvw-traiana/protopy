from argparse import ArgumentParser

from protopy_performance.generator import ProtoGenerator


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '-s', '--seed',
        type=int,
        help='Seed to use when generating Proto file',
        required=True,
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Protobuf IDL file to save output to',
        required=True,
    )
    parser.add_argument(
        '-b', '--binary-mask',
        type=str,
        help='''
    Protobuf binary file mask to save output to.

    Use '%d' in the mask where you want the the number assigned to
    this file during generation to appear.  See also
    `--num-binaries'.
    ''',
        required=False,
        default='proto-%d.bin',
    )
    parser.add_argument(
        '-n', '--num-binaries',
        type=int,
        help='How many binary outputs to produce.',
        required=False,
        default=0,
    )
    parser.add_argument(
        '-x', '--binary-seeds',
        type=int,
        help='Seeds for binary proto files.',
        required=False,
        action='append',
        nargs='+',
    )

    args = parser.parse_args()
    generator = ProtoGenerator(args.seed)

    with open(args.output, 'w') as o:
        for line in generator.render().split('\n'):
            if line.strip():
                print(line, file=o)

    if args.num_binaries:
        generator.bin(
            args.output,
            args.binary_seeds,
            args.binary_mask,
            args.num_binaries,
        )


main()
