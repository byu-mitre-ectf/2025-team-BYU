#cd ./decoder
python -m ectf25_design.gen_secrets global.secrets/secrets.json 0 1 2 3 4 5 6 7 8 --force
docker build -t build-decoder .
#docker run --rm -v ./build_out:/out -v ./:/decoder -v ./../secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
