# frozen_string_literal: true

module UserApi
  module V1
    # Responsible for CRUD for api keys
    class APIKeys < Grape::API
      resource :api_keys do
        before do
          unless current_account.otp_enabled
            error!('Only accounts with enabled 2FA alowed', 400)
          end

          unless Vault::TOTP.validate?(current_account.uid, params[:totp_code])
            error!('Your code is invalid', 422)
          end
        end

        desc 'List all api keys for current account.'
        params do
          requires :totp_code, type: String, desc: 'Code from Google Authenticator', allow_blank: false
        end
        get do
          present current_account.api_keys, with: Entities::APIKey
        end

        desc 'Return an api key by uid'
        params do
          requires :uid, type: String, allow_blank: false
          requires :totp_code, type: String, desc: 'Code from Google Authenticator', allow_blank: false
        end
        get ':uid' do
          api_key = current_account.api_keys.find_by!(uid: params[:uid])
          present api_key, with: Entities::APIKey
        end

        desc 'Create an api key'
        params do
          requires :public_key, type: String,
                                allow_blank: false
          optional :scopes, type: String,
                            allow_blank: false,
                            desc: 'comma separated scopes'
          optional :expires_in, type: String,
                                allow_blank: false,
                                desc: 'expires_in duration in seconds'
          requires :totp_code, type: String, desc: 'Code from Google Authenticator', allow_blank: false
        end
        post do
          declared_params = declared(params, include_missing: false).except(:totp_code)
          api_key = current_account.api_keys.create(declared_params)
          if api_key.errors.any?
            error!(api_key.errors.full_messages.to_sentence, 422)
          end

          present api_key, with: Entities::APIKey
        end

        desc 'Updates an api key'
        params do
          requires :uid, type: String, allow_blank: false
          optional :public_key, type: String,
                                allow_blank: false
          optional :scopes, type: String,
                            allow_blank: false,
                            desc: 'comma separated scopes'
          optional :expires_in, type: String,
                                allow_blank: false,
                                desc: 'expires_in duration in seconds'
          optional :state, type: String, desc: 'State of API Key. "active" state means key is active and can be used for auth',
                           allow_blank: false
          requires :totp_code, type: String, desc: 'Code from Google Authenticator', allow_blank: false
        end
        patch ':uid' do
          declared_params = declared(params, include_missing: false).except(:totp_code)
          api_key = current_account.api_keys.find_by!(uid: params[:uid])
          unless api_key.update(declared_params)
            error!(api_key.errors.full_messages.to_sentence, 422)
          end

          present api_key, with: Entities::APIKey
        end

        desc 'Delete an api key'
        params do
          requires :uid, type: String, allow_blank: false
          requires :totp_code, type: String, desc: 'Code from Google Authenticator', allow_blank: false
        end
        delete ':uid' do
          api_key = current_account.api_keys.find_by!(uid: params[:uid])
          api_key.destroy
          status 204
        end
      end
    end
  end
end
