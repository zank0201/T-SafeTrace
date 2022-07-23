#make examples-install
#cd out/host && scp ./track-rs root@10.42.0.172:/usr/bin
#cd ../ta && scp ./6c9f044f-175a-4569-9973-caaa660f8216.ta root@10.42.0.172:/lib/optee_armtz
#cd ../..
make examples-install
cd out/host && scp ./performance root@10.42.0.172:/usr/bin
cd ../ta && scp ./f4302b06-c845-41a5-a06e-b1313e075b05.ta root@10.42.0.172:/lib/optee_armtz
cd ../..