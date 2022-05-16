#Import global packages
import argparse
import slidecode

def main():
    parser = argparse.ArgumentParser(
        description = slidecode.SLIDECODE_DESCRIPTION
    )

    parser.add_argument("--in-file", "-i", 
        type=str, dest="in_file", help=slidecode.SLIDECODE_IN_HELP
    )

    parser.add_argument("--out-file", "-o",
        type=str, dest="out_file", help=slidecode.SLIDECODE_OUT_HELP
    )

    parser.add_argument("--verbose", '-v', 
        dest="verbose", action="store_true", help=slidecode.SLIDECODE_VERBOSE_HELP)

    parser.add_argument("--keys", '-k', 
        dest="keys", help=slidecode.SLIDECODE_KEY_HELP)

    parser.add_argument("--trailer", "-t",
        dest="trailer", help=slidecode.SLIDECODE_TRAILER_HELP)

    args = parser.parse_args()
    sc = slidecode.SlideCode(infile=args.in_file, outfile=args.out_file, verbose=args.verbose, key_string=args.keys, trailer=args.trailer)
    sc.run()



if __name__ == "__main__":
    main()