cd ./decoder
docker build -t decoder .
docker run --rm -v .\build_out:/out -v .\:/decoder -v .\..\secrets:/secrets -e DECODER_ID=0xdeadbeef decoder