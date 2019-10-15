require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements

set :port, 3001
set :bind, '0.0.0.0'

class GHAapp < Sinatra::Application 

    PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

    WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

    APP_IDentifier = ENV['GITHUB_APP_IDENTIFIER']


    configure :development do
        set :logging, Logger::DEBUG
      end

    before '/event_handler' do
        get_payload_request(request)
        verify_webhook_signature

        unless @payload['repository'].nil?
            halt 400 if (@payload['repository']['name'] =~ /[0-9A-Za-z\-\_]+/).nil?
        end

        authenticate_app
        authenticate_installation(@payload)
    end

    post '/payload' do
        request.body.rewind
        payload_body = request.body.read
        verify_signature(payload_body)
        # push = JSON.parse(params[:payload])
        push = JSON.parse(payload_body)
        puts "I got some JSON: #{push.inspect}"
    end

    def verify_signature(payload_body)
        signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), ENV['SECRET_TOKEN'], payload_body)
        return halt 500, "Signatures didn't match!" unless Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])
    end

    post '/event_handler' do
        case request.env['HTTP_X_GITHUB_EVENT']
        when 'check_suite'
            if @payload['action'] == 'requested' || @payload['action'] == 'rerequested'
                create_check_run
            end
        end




    end
    
    helpers do

        def create_check_run
            check_run = @installation_client.post("repos/#{@payload['repository']['full_name']}/check_runs", {
                accept: 'application/vnd.github.antiope-preview+json',
                name: 'Octo RuboCop',
                head_sha: @payload['check_run'].nil ? @payload['check_suite']['head_sha'] : @payload['check_run']['head_sha']
            })
        end

        def get_payload_request(request)

            request.body.rewind
    
            @payload_raw = request.body.read
            begin
                @payload = JSON.parse @payload_raw
            rescue => e
                fail 'Invalid JSON (#{e}): #{@payload_raw}'
            end
        end

        def verify_webhook_signature
            their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
            method, their_digest = their_signature_header.split('=')
            our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
            halt 401 unless their_digest == our_digest
      
            logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
            logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
          end

        def authenticate_app
            payload = {
                iat: Time.now.to_i,

                exp: Time.now.to_i + (10 * 60),

                iss: APP_IDENTIFIER
            }

            jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

            @app_client ||= Octokit::Client.new(bearer_token: jwt)
        end

        def authenticate_installation 
            @installation_id = payload['installation']['id']
            @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
            @installation_client = Octokit::Client.new(bearer_token: @installation_token)
        end


    end

    run! if __FILE__ == $0
end
