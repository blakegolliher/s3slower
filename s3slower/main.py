# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

import os
import sys
import urllib3
import logging
import argparse
import asyncio
from pathlib import Path
try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata

import yaml
from bcc import BPF, __version__
from stevedore.named import NamedExtensionManager, ExtensionManager

from s3slower.logger import COLORS
from s3slower.utils import (
    InvalidArgument,
    set_signal_handler,
    await_until_event_or_timeout,
    parse_args_options_from_namespace,
    maybe_list_parse,
    maybe_bool_parse,
    flatten_keys,
)
from s3slower.s3ops import S3StatsCollector, logger

urllib3.disable_warnings()

BASE_PATH = Path(__file__).parents[1]
ENTRYPOINT_GROUP = "drivers"

# Available drivers through entry points
entry_points = metadata.entry_points()
if sys.version_info >= (3, 10):
    ENTRYPOINTS = entry_points.select(group=ENTRYPOINT_GROUP)
else:
    ENTRYPOINTS = entry_points.get(ENTRYPOINT_GROUP, [])

available_drivers = sorted(set([e.name for e in ENTRYPOINTS]))

# Fallback for development/direct execution without installation
if not available_drivers:
    # Import drivers directly
    from s3slower.drivers import ScreenDriver, PrometheusDriver
    
    # Create mock entry points for development
    class MockEntryPoint:
        def __init__(self, name, plugin):
            self.name = name
            self.plugin = plugin
            
    ENTRYPOINTS = [
        MockEntryPoint("screen", ScreenDriver),
        MockEntryPoint("prometheus", PrometheusDriver),
    ]
    available_drivers = ["screen", "prometheus"]


def validate_args(conf_args=None):
    """
    Validate the arguments provided by the user.
    This function checks that all CLI options specified as command line arguments
    or in the configuration file are valid.
    """
    conf_keys = []
    if conf_args:
        conf_keys = [ck for ck in flatten_keys(conf_args) if ck not in available_drivers]
    cli_keys = [ck for ck in sys.argv[1:] if ck.startswith("-")]
    all_keys = conf_keys + cli_keys

    all_options = set()
    if available_drivers == ["screen", "prometheus"]:
        # Development mode - import parsers directly
        from s3slower.drivers import ScreenDriver, PrometheusDriver
        all_parsers = [conf_parser, ScreenDriver.parser, PrometheusDriver.parser]
    else:
        mgr = ExtensionManager(namespace=ENTRYPOINT_GROUP)
        all_parsers = [conf_parser] + [ext.plugin.parser for ext in mgr.extensions]

    # Collect all options from all parsers
    for parser in all_parsers:
        for action in parser._actions:
            all_options.update(action.option_strings)
    available_keys = {k.replace("-", "_").strip("_") for k in all_options}
    
    # Check if any unknown options are provided
    for key in all_keys:
        refined_key = key.lstrip("-").replace("-", "_").split("=")[0]
        if refined_key and refined_key not in available_keys:
            raise InvalidArgument(f"Unknown option '{key}'")


class HelpFormatter(argparse.HelpFormatter):
    """Custom help formatter for argparse to format help messages with colors"""

    def format_help(self):
        """Format the help message to include usage, options, and their descriptions"""
        prog = self._prog
        usages = []
        help_text = []
        required_mark = " " + COLORS.intense_red("\u26A0")
        
        # Helper function to clean up usage strings
        strip = lambda txt: txt.replace(prog, "").replace("[-h]", "").strip("usage:").strip()
        
        # Gather all parsers and their actions
        all_parsers = [
            ("Configuration Options", conf_parser),
        ]
        
        # Add extension parsers
        if available_drivers == ["screen", "prometheus"]:
            # Development mode
            from s3slower.drivers import ScreenDriver, PrometheusDriver
            all_parsers.append(("ScreenDriver Options", ScreenDriver.parser))
            all_parsers.append(("PrometheusDriver Options", PrometheusDriver.parser))
        else:
            mgr = ExtensionManager(namespace=ENTRYPOINT_GROUP)
            for ext in mgr.extensions:
                all_parsers.append((f"{ext.plugin.__name__} Options", ext.plugin.parser))
        
        # Collect usage strings and format help text
        for section_name, parser in all_parsers:
            usages.append(strip(
                argparse.HelpFormatter._format_usage(self, None, parser._actions, [], None))
            )
            help_text.append(f"\n{COLORS.intense_blue(section_name)}:")
            max_option_length = max(len(", ".join(action.option_strings)) for action in parser._actions)
            
            for action in parser._actions:
                options = ", ".join(action.option_strings)
                if "--driver" in options:
                    required = required_mark
                else:
                    required = required_mark if action.required else "  "
                
                if action.choices:
                    choices = f" {COLORS.yellow('[ choices')}: {', '.join(map(str, action.choices))} {COLORS.yellow(']')}"
                else:
                    choices = ""
                
                default_text = f" {COLORS.green('[ default')}: {action.default!r} {COLORS.green(']')}" if (action.default is not None and action.default != argparse.SUPPRESS) else ""
                help_section = f"{action.help}{choices}{default_text}"
                help_section = ("\n" + " " * (max_option_length + 5)).join(help_section.splitlines())
                help_text.append(f"  {options.ljust(max_option_length)}:{required} {help_section}")
        
        # Construct the final help message
        return f"Usage: {prog} " + " ".join(usages) + f"\n\n({required_mark} - option is required if driver is enabled )" + "\n".join(help_text) + "\n\n"


# Configuration parser
conf_parser = argparse.ArgumentParser(formatter_class=HelpFormatter)
conf_parser.add_argument(
    '-d', '--driver',
    help="Driver to enable. User can specify multiple options.",
    choices=available_drivers, action='append', required=False, default=None
)
conf_parser.add_argument(
    "--debug", action="store_true",
    help="Enable debug prints."
)
conf_parser.add_argument(
    "-i", "--interval", default=5, type=int,
    help="Output interval, in seconds."
)
conf_parser.add_argument(
    "-p", "--pid", type=int,
    help="Process ID to monitor (monitor all processes if not specified)."
)
conf_parser.add_argument(
    "--min-latency-ms", default=0, type=int,
    help="Minimum latency threshold in milliseconds."
)
conf_parser.add_argument(
    "--ebpf", action="store_true",
    help="Dump BPF program text and exit."
)
conf_parser.add_argument(
    "-C", "--cfg", default=None,
    help="Config yaml. When provided it takes precedence over command line arguments."
)


async def _exec():
    """Main execution function to set up and run the BPF program and drivers"""
    exit_error = None
    stop_event = asyncio.Event()
    args, remaining = conf_parser.parse_known_args()
    cfg_opts = None
    
    if args.cfg:
        if not os.path.exists(args.cfg):
            raise FileNotFoundError(args.cfg)
        with open(args.cfg) as f:
            cfg_opts = yaml.safe_load(f)
            if cfg_opts:
                args = parse_args_options_from_namespace(namespace=cfg_opts, parser=conf_parser)
                args.driver = sorted(set(available_drivers).intersection(set(cfg_opts.keys())))

    # Check for --ebpf flag first (doesn't require driver)
    if args.ebpf:
        bpf_file = BASE_PATH.joinpath("s3slower.c")
        if not bpf_file.exists():
            raise FileNotFoundError(f"BPF program not found: {bpf_file}")
        with bpf_file.open() as f:
            print(f.read())
        return 0

    # Validate arguments
    try:
        validate_args(cfg_opts)
    except InvalidArgument as e:
        conf_parser.error(str(e))

    drivers = args.driver
    if not drivers:
        conf_parser.error("No driver specified.")

    logger.info(f"BPF version: {__version__}")
    try:
        collector_version = BASE_PATH.joinpath("version.txt").read_text().strip('\n')
    except:
        collector_version = "0.0+local.dummy"
    
    logger.info(f"S3Slower<{COLORS.intense_blue(collector_version)}> initialization")
    
    display_options = [
        ("drivers", drivers),
        ("interval", args.interval),
        ("pid", args.pid),
        ("min-latency-ms", args.min_latency_ms),
        ("config", args.cfg),
    ]
    
    logger.info(
        f"Configuration options: "
        f"{', '.join(f'{k}={v}' for k, v in display_options)}"
    )

    # Read BPF program text
    bpf_file = BASE_PATH.joinpath("s3slower.c")
    if not bpf_file.exists():
        raise FileNotFoundError(f"BPF program not found: {bpf_file}")
    
    debug = args.debug
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    # Initialize S3 stats collector
    collector = S3StatsCollector(args)
    
    # Initialize drivers
    if available_drivers == ["screen", "prometheus"]:
        # Development mode - use mock manager
        class MockDriverManager:
            def __init__(self, drivers, args):
                self.extensions = []
                driver_map = {"screen": ScreenDriver, "prometheus": PrometheusDriver}
                for driver_name in drivers:
                    if driver_name in driver_map:
                        driver_obj = driver_map[driver_name](common_args=args)
                        ext = type('MockExt', (), {'name': driver_name, 'obj': driver_obj})()
                        self.extensions.append(ext)
            
            def map(self, func):
                return [func(ext) for ext in self.extensions]
            
            def map_method(self, method_name, *args, **kwargs):
                results = []
                for ext in self.extensions:
                    method = getattr(ext.obj, method_name)
                    results.append(method(*args, **kwargs))
                return results
        
        from s3slower.drivers import ScreenDriver, PrometheusDriver
        mgr = MockDriverManager(drivers, args)
    else:
        mgr = NamedExtensionManager(
            namespace=ENTRYPOINT_GROUP,
            invoke_on_load=True,
            names=drivers,
            invoke_kwds=dict(common_args=args)
        )

    def on_exit(sig=None, frame=None):
        """Teardown drivers gracefully on exit"""
        logger.info("Exiting...")
        stop_event.set()

    set_signal_handler(on_exit, asyncio.get_running_loop())

    # Setup drivers
    if cfg_opts:
        setup_coros = mgr.map(lambda e: e.obj.setup(namespace=cfg_opts[e.name]))
    else:
        setup_coros = mgr.map_method("setup", remaining)
    
    try:
        await asyncio.gather(*setup_coros)
    except InvalidArgument as e:
        exit_error = e
        conf_parser.print_help()
        on_exit()
    except Exception as e:
        exit_error = e
        on_exit()

    if not stop_event.is_set():
        # Attach eBPF probes
        try:
            collector.attach()
            collector.start()
            logger.info("All good! S3Slower has been attached and is monitoring S3 operations.")
        except Exception as e:
            logger.error(f"Failed to attach S3 monitoring: {e}")
            exit_error = e
            on_exit()

    # Main collection loop
    while not stop_event.is_set():
        canceled = await await_until_event_or_timeout(timeout=args.interval, stop_event=stop_event)
        if canceled:
            break

        data = collector.collect_stats(interval=args.interval)
        if data.empty:
            continue
        
        # Send data to all drivers
        await asyncio.gather(*mgr.map_method("store_sample", data=data))

    # Cleanup
    collector.stop()
    await asyncio.gather(*mgr.map_method("teardown"))
    
    if exit_error:
        logger.error(str(exit_error))


def main():
    """Main entry point"""
    try:
        return asyncio.run(_exec())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0


if __name__ == "__main__":
    main() 