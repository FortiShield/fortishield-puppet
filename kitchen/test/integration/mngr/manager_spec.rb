control 'fortishield-manager' do
  title 'Fortishield manager tests'
  describe 'Checks Fortishield manager correct version, services and daemon ownership'

  describe package('fortishield-manager') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '5.0.0-1' }
  end

  # Verifying service
  describe service('fortishield-manager') do
    it { is_expected.to be_installed }
    it { is_expected.to be_enabled }
    it { is_expected.to be_running }
  end

  # Verifying daemons
  fortishield_daemons = {
    'fortishield-authd' => 'root',
    'fortishield-execd' => 'root',
    'fortishield-analysisd' => 'fortishield',
    'fortishield-syscheckd' => 'root',
    'fortishield-remoted' => 'fortishield',
    'fortishield-logcollector' => 'root',
    'fortishield-monitord' => 'fortishield',
    'fortishield-db' => 'fortishield',
    'fortishield-modulesd' => 'root',
  }

  fortishield_daemons.each do |key, value|
    describe processes(key) do
      its('users') { is_expected.to eq [value] }
    end
  end
end
