from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).parent


def read_lines(filename: str) -> list[str]:
    return [
        line
        for line in (ROOT / filename).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


setup(
    name="GoodWinRM",
    version="0.2.0",
    description="Python WinRM interactive shell with file transfer",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    url="https://github.com/SS4ar/goodwinrm",
    author="SS4ar",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=read_lines("requirements.txt"),
    extras_require={
        "kerberos": [
            "pykerberos>=1.2.1,<2; platform_system != 'Windows'",
            "winkerberos>=0.5.0; platform_system == 'Windows'",
        ],
        "dev": [
            "build>=1.2,<2",
            "mypy>=1.10,<2",
            "pytest>=8,<9",
            "pytest-cov>=5,<7",
            "ruff>=0.6,<1",
            "types-requests>=2.32",
        ],
    },
    entry_points={"console_scripts": ["goodwinrm=goodwinrm.goodwinrm:main"]},
)
