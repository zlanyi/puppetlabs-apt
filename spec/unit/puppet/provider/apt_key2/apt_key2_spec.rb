require 'spec_helper'

# TODO: needs some cleanup/helper to avoid this misery
module Puppet::Provider::AptKey2; end
require 'puppet/provider/apt_key2/apt_key2'

RSpec.describe Puppet::Provider::AptKey2::AptKey2 do
  subject(:provider) { described_class.new }

  let(:context) { instance_double('Puppet::ResourceApi::BaseContext') }

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

  describe '.key_line_to_hash(pub, fpr)' do
    subject(:result) { described_class.key_line_to_hash(pub, fpr) }

    let(:pub) { "pub:-:4096:#{key_type}:7638D0442B90D010:1416603673:1668891673::-:::scSC:::::::" }
    let(:fpr) { "fpr:::::::::#{id}:" }

    let(:key_type) { :foo }

    let(:short) { 'a' * 8 }
    let(:long) { ('1' * 8) + short }
    let(:id) { 'f' * (40 - 16) + long }

    it('returns the id') { expect(result[:id]).to eq id }
    it('returns the long id') { expect(result[:long]).to eq long }
    it('returns the short id') { expect(result[:short]).to eq short }

    [[1, :rsa], [17, :dsa], [18, :ecc], [19, :ecdsa], [:foo, :unrecognized]].each do |key_type, value|
      context "with a key type of #{key_type}" do
        let(:key_type) { key_type }

        it("returns #{value.inspect} as key type") { expect(result[:type]).to eq value }
      end
    end
  end

  describe '#get' do
    let(:apt_key_cmd) { instance_double('Puppet::ResourceApi::Command') }
    let(:process) { instance_double('ChildProcess::AbstractProcess') }
    let(:io) { instance_double('ChildProcess::AbstractIO') }
    let(:stdout) do
      StringIO.new <<EOS
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
    end

    before(:each) do
      allow(Puppet::ResourceApi::Command).to receive(:new).and_return(apt_key_cmd)
      allow(process).to receive(:io).and_return(io)
    end

    it 'processes input' do
      # expect(apt_key_cmd).to receive(:run).with(context, any_args).and_yield(process)
      # expect(io).to receive(:stdout).and_return(stdout)
      expect(provider).to receive(:`).with('apt-key adv --list-keys --with-colons --fingerprint --fixed-list-mode 2>/dev/null').and_return(stdout) # rubocop:disable RSpec/SubjectStub
      expect(provider.get(context)).to eq [
        { ensure: 'present',
          id: '126C0D24BD8A2942CC7DF8AC7638D0442B90D010',
          fingerprint: '126C0D24BD8A2942CC7DF8AC7638D0442B90D010',
          long: '7638D0442B90D010',
          short: '2B90D010',
          size: 4096,
          type: :rsa,
          created: '2014-11-21 21:01:13 +0000',
          expiry: '2022-11-19 21:01:13 +0000',
          expired: false },
        { ensure: 'present',
          id: 'D21169141CECD440F2EB8DDA9D6D8F6BC857C906',
          fingerprint: 'D21169141CECD440F2EB8DDA9D6D8F6BC857C906',
          long: '9D6D8F6BC857C906',
          short: 'C857C906',
          size: 4096,
          type: :rsa,
          created: '2014-11-21 21:13:37 +0000',
          expiry: '2022-11-19 21:13:37 +0000',
          expired: false },
      ]
    end
  end

  describe '#set(context, changes)' do
    let(:apt_key_cmd) { instance_double('Puppet::ResourceApi::Command') }
    let(:process) { instance_double('ChildProcess::AbstractProcess') }
    let(:io) { instance_double('ChildProcess::AbstractIO') }
    let(:id) { 'A' * 40 }

    before(:each) do
      allow(Puppet::ResourceApi::Command).to receive(:new).and_return(apt_key_cmd)
    end

    context 'when passing in empty changes' do
      it 'does nothing' do
        expect { provider.set(context, {}) }.not_to raise_error
      end
    end

    context 'when managing a up-to-date key' do
      it 'does nothing' do
        expect {
          provider.set(context, id => {
                         is: {
                           id: id, ensure: :present
                         },
                         should: {
                           id: id, ensure: :present
                         },
                       })
        }.not_to raise_error
      end
    end

    context 'when managing an absent key' do
      it 'does nothing' do
        provider.set(context, id =>
        {
          is: nil,
          should: {
            id: id,
            ensure: :absent,
          },
        })
      end
    end

    context 'when fetching a key from the keyserver' do
      let(:creating_ctx) { instance_double('Puppet::ResourceApi::BaseContext', 'creating_ctx') }

      it 'updates the system' do
        expect(context).to receive(:creating).with(id).and_yield(creating_ctx)
        expect(apt_key_cmd).to receive(:run).with(creating_ctx, 'adv', '--keyserver', 'keyserver.example.com', '--recv-keys', id, noop: false).and_return 0
        provider.set(context, id =>
        {
          is: nil,
          should: {
            id: id,
            ensure: :present,
            server: :'keyserver.example.com',
          },
        })
      end
    end

    context 'when deleting a key' do
      let(:deleting_ctx) { instance_double('Puppet::ResourceApi::BaseContext', 'deleting_ctx') }

      it 'updates the system' do
        expect(context).to receive(:deleting).with(id).and_yield(deleting_ctx)
        expect(apt_key_cmd).to receive(:run).with(deleting_ctx, 'del', id, noop: false).and_return 0
        provider.set(context, id =>
        {
          is: {
            id: id,
            ensure: :present,
            server: :'keyserver.ubuntu.com',
          },
          should: {
            id: id,
            ensure: :absent,
          },
        })
      end
    end
  end
end
