control 'fortishield-agent' do
  title 'Fortishield agent tests'
  describe 'Checks Fortishield agent correct version, services and daemon ownership'

  describe package('fortishield-agent') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '5.0.0-1' }
  end

  describe service('fortishield-agent') do
    it { is_expected.to be_installed }
    it { is_expected.to be_enabled }
    it { is_expected.to be_running }
  end

  # Verifying daemons
  fortishield_daemons = {
    'fortishield-agentd' => 'fortishield',
    'fortishield-execd' => 'root',
    'fortishield-modulesd' => 'root',
    'fortishield-syscheckd' => 'root',
    'fortishield-logcollector' => 'root'
  }

  fortishield_daemons.each do |key, value|
    describe processes(key) do
      its('users') { is_expected.to eq [value] }
    end
  end
end
