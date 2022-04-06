import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="radius-eap-mschapv2-client", # Replace with your own username
    version="1.0.4",
    author="mneitsabes",
    author_email="mneitsabes@nulloz.be",
    description="A RADIUS EAP-MSCHAPv2 client",
    long_description=long_description,
    long_description_content_type="text/markdown",
	keywords = ['radius', 'EAP', 'MSCHAPv2'],
    url="https://github.com/mneitsabes/RADIUS-EAP-MSCHAPv2-Python-client",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
	install_requires=[       
          'pycryptodome',
      ],
    python_requires='>=3.6',
)