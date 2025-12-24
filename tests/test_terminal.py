"""
Tests for terminal handling functions in s3slower.core.

These functions configure the terminal to minimize control character
interference during trace output.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


class TestSetupTerminal:
    """Tests for setup_terminal function."""

    def test_returns_none_when_not_tty(self) -> None:
        """Returns None when stdin is not a TTY."""
        from s3slower.core import setup_terminal

        with patch.object(sys.stdin, "isatty", return_value=False):
            result = setup_terminal()

        assert result is None

    @patch("termios.tcgetattr")
    @patch("termios.tcsetattr")
    @patch.object(sys.stdin, "isatty", return_value=True)
    def test_returns_old_settings_when_tty(
        self,
        mock_isatty: MagicMock,
        mock_tcsetattr: MagicMock,
        mock_tcgetattr: MagicMock,
    ) -> None:
        """Returns old terminal settings when stdin is a TTY."""
        from s3slower.core import setup_terminal

        mock_old_settings = [0, 0, 0, 0, 0, 0, []]
        mock_tcgetattr.return_value = mock_old_settings

        result = setup_terminal()

        assert result == mock_old_settings
        mock_tcgetattr.assert_called()
        mock_tcsetattr.assert_called()

    @patch("termios.tcgetattr")
    @patch.object(sys.stdin, "isatty", return_value=True)
    def test_handles_exception_gracefully(
        self, mock_isatty: MagicMock, mock_tcgetattr: MagicMock
    ) -> None:
        """Handles exceptions during terminal setup gracefully."""
        from s3slower.core import setup_terminal

        mock_tcgetattr.side_effect = Exception("Terminal error")

        result = setup_terminal()

        # Should return None on error rather than raising
        assert result is None


class TestRestoreTerminal:
    """Tests for restore_terminal function."""

    def test_does_nothing_with_none(self) -> None:
        """Does nothing when old_settings is None."""
        from s3slower.core import restore_terminal

        # Should not raise
        restore_terminal(None)

    def test_does_nothing_when_not_tty(self) -> None:
        """Does nothing when stdin is not a TTY."""
        from s3slower.core import restore_terminal

        with patch.object(sys.stdin, "isatty", return_value=False):
            # Should not raise even with valid settings
            restore_terminal([0, 0, 0, 0, 0, 0, []])

    @patch("termios.tcsetattr")
    @patch.object(sys.stdin, "isatty", return_value=True)
    def test_restores_settings(
        self, mock_isatty: MagicMock, mock_tcsetattr: MagicMock
    ) -> None:
        """Restores terminal settings."""
        from s3slower.core import restore_terminal

        old_settings = [0, 0, 0, 123, 0, 0, []]
        restore_terminal(old_settings)

        mock_tcsetattr.assert_called_once()

    @patch("termios.tcsetattr")
    @patch.object(sys.stdin, "isatty", return_value=True)
    def test_handles_exception_gracefully(
        self, mock_isatty: MagicMock, mock_tcsetattr: MagicMock
    ) -> None:
        """Handles exceptions during terminal restore gracefully."""
        from s3slower.core import restore_terminal

        mock_tcsetattr.side_effect = Exception("Terminal error")

        # Should not raise
        restore_terminal([0, 0, 0, 0, 0, 0, []])


class TestFlushStdin:
    """Tests for flush_stdin function."""

    def test_does_nothing_when_not_tty(self) -> None:
        """Does nothing when stdin is not a TTY."""
        from s3slower.core import flush_stdin

        with patch.object(sys.stdin, "isatty", return_value=False):
            # Should not raise
            flush_stdin()

    @patch("select.select")
    @patch("termios.tcflush")
    @patch.object(sys.stdin, "isatty", return_value=True)
    def test_flushes_when_input_available(
        self,
        mock_isatty: MagicMock,
        mock_tcflush: MagicMock,
        mock_select: MagicMock,
    ) -> None:
        """Flushes stdin when input is available."""
        from s3slower.core import flush_stdin

        # Simulate input available
        mock_select.return_value = ([sys.stdin], [], [])

        flush_stdin()

        mock_tcflush.assert_called_once()

    @patch("select.select")
    @patch.object(sys.stdin, "isatty", return_value=True)
    def test_does_nothing_when_no_input(
        self, mock_isatty: MagicMock, mock_select: MagicMock
    ) -> None:
        """Does nothing when no input is available."""
        from s3slower.core import flush_stdin

        # Simulate no input available
        mock_select.return_value = ([], [], [])

        # Should not raise
        flush_stdin()

    @patch("select.select")
    @patch.object(sys.stdin, "isatty", return_value=True)
    def test_handles_exception_gracefully(
        self, mock_isatty: MagicMock, mock_select: MagicMock
    ) -> None:
        """Handles exceptions during flush gracefully."""
        from s3slower.core import flush_stdin

        mock_select.side_effect = Exception("Select error")

        # Should not raise
        flush_stdin()
