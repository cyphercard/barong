# frozen_string_literal: true

require 'barong/security/access_token'

module ManagementAPI
  module V1
    class OTP < Grape::API
      helpers do
        def generate_signed_payload(payload)
          require 'openssl'
          keychain = { barong: Barong::Security.private_key }
          algorithms = { barong: 'RS256' }
          JWT::Multisig.generate_jwt(payload, keychain, algorithms)
        end
      end

      desc 'OTP related routes'
      resource :otp do
        desc "Sign request with barong signature" do
          @settings[:scope] = :otpsign
        end
        params do
          requires :account_uid, type: String, allow_blank: false, desc: 'Account UID'
          requires :otp_code, type: Integer, allow_blank: false, desc: 'Code from Google Authenticator'
          requires :request_data, type: Hash, allow_blank: false, desc: 'Request data from App Logic'
        end
        post '/sign' do
          declared_params = declared(params)
          account = Account.kept.active.find_by!(uid: declared_params[:account_uid])
          error!('Account has not enabled 2FA', 422) unless account.otp_enabled

          unless Vault::TOTP.validate?(account.uid, declared_params[:otp_code])
            error!('OTP code is invalid', 422)
          end

          generate_signed_payload(declared_params[:request_data])
        end
      end
    end
  end
end
