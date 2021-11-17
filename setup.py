from setuptools import *







if __name__ == "__main__":



    f = open("requirements.txt", 'r')

    dependencies = f.read().splitlines()

    f.close()

    setup(
    scripts = ["src/wappy"],
    name='wappalyzer-cli',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        dependencies
    ],
    
    
    )