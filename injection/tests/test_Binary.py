import pytest
from ElfInjection.Binary import *


class TestElfBinary:
    @pytest.mark.parametrize(
        "binary_name",
        [
            "arm_android_bin",
        ],
    )
    def test_init_binary_valid(self, binary_name):
        binary = ElfBinary(binary_name)
        assert binary.getBinary()
        assert binary.getFileName() == binary_name
        assert binary._getTempName() == "temp"

    @pytest.mark.parametrize("binary_name", ["amd_bin", "", None])
    @pytest.mark.xfail
    def test_init_binary_invalid(self, binary_name):
        binary = ElfBinary(binary_name)
        assert binary.getBinary()
        assert binary.getFileName() == binary_name
        assert binary._getTempName() == "temp"
