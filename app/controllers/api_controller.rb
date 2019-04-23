class ApiController < ApplicationController
  skip_before_action :verify_authenticity_token
  before_action :check_for_pull_request
  before_action :verify_github_secret

  def pull_request
    pr = params['api'].try(:[], 'pull_request').try(:to_unsafe_h)

    return head 422 if pr.nil?

    approve_request(pr) if files_match?(pr) && needs_review?(pr)
  
    head 200
  end

  def files_match?(pull_request)
    auto_approve = ignored_files(pull_request)

    changed = changed_files(pull_request)

    return false if changed.nil?

    files_match = true
    changed.each do |changed_file|
      match = false
      auto_approve.each do |pattern|
        next if match

        match = true if match?(pattern, changed_file)
      end
      unless match
        files_match = false
        break
      end
    end

    if files_match
      logger.info "All files match, #{pull_request['base']['repo']['full_name']} can be automatically merged into #{pull_request['head']['repo']['full_name']}"
    else
      logger.info 'Some of the changed files are not in .auto-approve; this PR requires human review'
    end

    files_match
  end

  def needs_review?(pull_request)
    uri = URI.parse(pull_request['url'] + '/reviews')
    request = ::Net::HTTP::Get.new(
      uri,
      {
        'Authorization' => "token #{ENV['GITHUB_API_KEY']}"
      }
    )

    response = ::Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.request(request)
    end

    return true unless response.code == '200'

    last_review = JSON.parse(response.body).last
    return true if last_review.nil?

    review_is_current = last_review['commit_id'] == pull_request['head']['sha']
    review_is_approved = last_review['state'] == 'APPROVED'

    if review_is_current && review_is_approved
      logger.info "PR has already been approved, no action needed"
      return false
    else
      logger.info "PR needs review"
      return true
    end
  end

  def match?(pattern, file)
    return false if pattern.blank?

    pattern.gsub!('/', '\/')
    pattern.gsub!('*', '[^\/]*')
    regex_pattern = if pattern.start_with?('\/')
      pattern.gsub!(/^\\\//, '')
      /^#{pattern}$/ # Match the pattern exactly
    else
      /#{pattern}$/ # Only match the end of the file name
    end

    file =~ regex_pattern
  end

  def approve_request(pull_request)
    uri = URI(pull_request['url'] + '/reviews')
    request = ::Net::HTTP::Post.new(
      uri,
      {
        'Content-Type' => 'application/json',
        'Authorization' => "token #{ENV['GITHUB_API_KEY']}"
      }
    )

    sha = pull_request['head']['sha']

    request.body = {
      commit_id: sha,
      event: 'APPROVE',
      body: "This PR has been auto-approved since it contains changes that don't require a human review."
    }.to_json

    ::Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.request(request)
    end
  end

  def changed_files(pull_request)
    uri = URI.parse(pull_request['url'] + '/files')
    request = ::Net::HTTP::Get.new(
      uri,
      {
        'Authorization' => "token #{ENV['GITHUB_API_KEY']}"
      }
    )

    response = ::Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.request(request)
    end

    return unless response.code == '200'

    files = JSON.parse(response.body)

    file_names = []
    files.each do |file|
      file_names << file['filename']
    end

    file_names
  end

  def ignored_files(pull_request)
    base_url = pull_request['base']['repo']['url']
    sha = pull_request['base']['sha']

    uri = URI.parse("#{base_url}/contents/.auto-approve?ref=#{sha}")
    request = ::Net::HTTP::Get.new(
      uri,
      {
        'Authorization' => "token #{ENV['GITHUB_API_KEY']}"
      }
    )

    response = ::Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.request(request)
    end

    return [] unless response.code == '200'

    content = JSON.parse(response.body)['content']
    Base64.decode64(content).split("\n")
  end

  def check_for_pull_request
    return if request.env['HTTP_X_HUB_EVENT'] == 'pull_request'

    head 400
    logger.info "Received a request that wasn't a pull_request: #{request.env['HTTP_X_HUB_EVENT']}"
  end

  def verify_github_secret
    return
    pr = params['api'].try(:[], 'pull_request').try(:to_unsafe_h).try(:[], 'base')
    project = pr.try(:[], 'repo').try(:[], 'full_name')
    branch = pr.try(:[], 'label')

    signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), ENV['GITHUB_SECRET_TOKEN'], request.raw_post)

    return if Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])

    head 401
    logger.info "Invalid authenticity token given by #{project} on branch #{branch}"
  end
end