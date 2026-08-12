# frozen_string_literal: true

require File.expand_path '../../test_helper', __FILE__

class RedirectBindingTest < RedmineSaml::TestCase
  # The IdP percent encoding the signature was built over: lowercase hex digits
  # and an encoded dot, neither of which Rack would produce when re-encoding.
  RAW_RELAY_STATE = 'http%3a%2f%2ftest%2ehost%2f'

  test 'keeps the raw percent encoding of the signed query parameters' do
    options = query_options_for "SAMLRequest=abc%2Fdef&RelayState=#{RAW_RELAY_STATE}&SigAlg=alg&Signature=sig"

    assert_equal 'abc%2Fdef', options[:raw_get_params]['SAMLRequest']
    assert_equal RAW_RELAY_STATE, options[:raw_get_params]['RelayState']
    assert_equal 'alg', options[:raw_get_params]['SigAlg']
  end

  test 'passes the decoded Signature separately from the raw signed parameters' do
    options = query_options_for 'SAMLRequest=req&RelayState=state&SigAlg=alg&Signature=sig%2Bvalue'

    assert_equal 'sig+value', options[:get_params]['Signature']
    assert_not_includes options[:raw_get_params].keys, 'Signature'
  end

  test 'rejects a duplicate SAMLRequest query parameter' do
    assert_nil query_options_for('SAMLRequest=first&SAMLRequest=second&SigAlg=alg&Signature=sig')
  end

  test 'rejects a duplicate SAMLResponse query parameter' do
    assert_nil query_options_for('SAMLResponse=first&SAMLResponse=second&SigAlg=alg&Signature=sig')
  end

  test 'rejects a duplicate RelayState query parameter' do
    assert_nil query_options_for('SAMLRequest=req&RelayState=first&RelayState=second&SigAlg=alg&Signature=sig')
  end

  test 'rejects a duplicate SigAlg query parameter' do
    assert_nil query_options_for('SAMLRequest=req&SigAlg=first&SigAlg=second&Signature=sig')
  end

  test 'rejects a duplicate Signature query parameter' do
    assert_nil query_options_for('SAMLRequest=req&SigAlg=alg&Signature=first&Signature=second')
  end

  test 'rejects a duplicate parameter whose name is percent encoded' do
    assert_nil query_options_for('SAMLRequest=first&SAMLReq%75est=second&SigAlg=alg&Signature=sig')
  end

  test 'accepts a duplicate parameter that is not part of the signed query' do
    options = query_options_for 'SAMLRequest=req&SigAlg=alg&Signature=sig&foo=first&foo=second'

    assert_equal 'req', options[:raw_get_params]['SAMLRequest']
  end

  test 'ignores query parameters that are not part of the signed query' do
    options = query_options_for 'SAMLRequest=req&SigAlg=alg&Signature=sig&foo=bar'

    assert_not_includes options[:raw_get_params].keys, 'foo'
  end

  test 'counts a signed query parameter that carries no value' do
    options = query_options_for 'SAMLRequest=req&SigAlg&Signature=sig'

    assert_equal '', options[:raw_get_params]['SigAlg']
    assert_nil query_options_for('SAMLRequest=req&SigAlg&SigAlg&Signature=sig')
  end

  test 'omits an absent signed query parameter instead of passing a nil value' do
    options = query_options_for 'SAMLRequest=req&SigAlg=alg&Signature=sig'

    assert_not_includes options[:raw_get_params].keys, 'RelayState'
    assert_equal({ 'SAMLRequest' => 'req', 'SigAlg' => 'alg' }, options[:raw_get_params])
  end

  private

  def query_options_for(query_string)
    request = ActionDispatch::TestRequest.create 'QUERY_STRING' => query_string

    RedmineSaml::RedirectBinding.query_options request
  end
end
