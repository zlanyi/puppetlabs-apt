require 'spec_helper_new'

# TODO: needs some cleanup/helper to avoid this misery
module Puppet::Provider::AptKey2; end
require 'puppet/provider/apt_key2/apt_key2'

RSpec.describe Puppet::Provider::AptKey2::AptKey2 do
  subject(:provider) { described_class.new }
    let(:context) { instance_double('context') }

  describe '#canonicalize(resources)' do
    it('works with empty inputs') { expect(provider.canonicalize([])).to eq [] }
    it('cleans up 0x hex numbers') { expect(provider.canonicalize([{ id: '0xabcd' }])).to eq [{ id: 'ABCD' }] }
    it('upcases bare hex numbers alone') { expect(provider.canonicalize([{ id: 'abcd' }])).to eq [{ id: 'ABCD' }] }
    it('leaves bare upper case hex numbers alone') { expect(provider.canonicalize([{ id: 'ABCD' }])).to eq [{ id: 'ABCD' }] }
    it('handles multiple inputs') do
      expect(provider.canonicalize([{ id: '0xabcd' },
                                    { id: 'abcd' },
                                    { id: 'ABCD' }]))
        .to eq [{ id: 'ABCD' },
                { id: 'ABCD' },
                { id: 'ABCD' }]
    end
    it('handles invalid inputs') do
      expect { provider.canonicalize([{ id: 'not a hex number' }]) }.not_to raise_error
    end
  end

  describe '#get' do
    let(:apt_key_cmd) { instance_double('Puppet::ResourceApi::Command') }
    let(:handle) { instance_double('handle') }
    let(:stdout) do
      StringIO.new(<<EOS
Executing: /tmp/apt-key-gpghome.4VkaIao1Ca/gpg.1.sh --list-keys --with-colons --fingerprint --fixed-list-mode
tru:t:1:1505150630:0:3:1:5
pub:-:4096:1:7638D0442B90D010:1416603673:1668891673::-:::scSC:::::::
rvk:::1::::::309911BEA966D0613053045711B4E5FF15B0FD82:80:
rvk:::1::::::FBFABDB541B5DC955BD9BA6EDB16CF5BB12525C4:80:
rvk:::1::::::80E976F14A508A48E9CA3FE9BC372252CA1CF964:80:
fpr:::::::::126C0D24BD8A2942CC7DF8AC7638D0442B90D010:
uid:-::::1416603673::15C761B84F0C9C293316B30F007E34BE74546B48::Debian Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>:
pub:-:4096:1:9D6D8F6BC857C906:1416604417:1668892417::-:::scSC:::::::
rvk:::1::::::FBFABDB541B5DC955BD9BA6EDB16CF5BB12525C4:80:
rvk:::1::::::309911BEA966D0613053045711B4E5FF15B0FD82:80:
rvk:::1::::::80E976F14A508A48E9CA3FE9BC372252CA1CF964:80:
fpr:::::::::D21169141CECD440F2EB8DDA9D6D8F6BC857C906:
uid:-::::1416604417::088FA6B00E33BCC6F6EB4DFEFAC591F9940E06F0::Debian Security Archive Automatic Signing Key (8/jessie) <ftpmaster@debian.org>:
EOS
                  )
    end

    it 'processes input' do
      allow(Puppet::ResourceApi::Command).to receive(:new).and_return(apt_key_cmd)
      expect(apt_key_cmd).to receive(:start_read).with(context, any_args).and_yield(handle)
      expect(handle).to receive(:stdout).and_yield(stdout)

      expect { provider.get(context) }.not_to raise_error
    end
  end
end
