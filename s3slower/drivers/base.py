# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

import abc
import argparse

from s3slower.logger import get_logger, COLORS
from s3slower.utils import InvalidArgument, parse_args_options_from_namespace


class DriverBase(abc.ABC):
    """Base class for all S3Slower output drivers"""
    
    parser = NotImplemented

    def __init__(self, common_args: argparse.Namespace):
        self.name = self.__class__.__name__.lower().replace("driver", "")
        self.common_args = common_args
        self.logger = get_logger(self.name, COLORS.blue)

    def __str__(self):
        raise NotImplementedError()

    __repr__ = __str__

    @abc.abstractmethod
    async def store_sample(self, data):
        """Store/export a sample of S3 latency data"""
        pass

    async def setup(self, args=(), namespace=None):
        """Setup the driver with configuration"""
        self.logger.info("Setting up driver.")
        if namespace:
            if not isinstance(namespace, dict):
                raise InvalidArgument(
                    f"Invalid argument '{namespace}'."
                    f" Check available arguments for {self.__class__.__name__} driver."
                )
            return parse_args_options_from_namespace(namespace=namespace, parser=self.parser)
        try:
            args, _ = self.parser.parse_known_args(args)
            return args
        except SystemExit as e:
            raise InvalidArgument() from e

    async def teardown(self):
        """Cleanup driver resources"""
        pass 