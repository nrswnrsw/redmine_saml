# frozen_string_literal: true

# Display texts of the SAML Sudo Mode confirmation prompt.
#
# Each text is optionally overridden by a plugin setting. A setting that is
# blank, including one that only contains whitespace, keeps the translation of
# the current locale, so a Redmine that configures none of them shows exactly
# the prompt it showed before these settings existed, in every language.
#
# The values are administrator supplied plain text and are rendered through
# normal Rails escaping. Nothing here marks them as HTML safe.
module OmniauthSamlSudoHelper
  def saml_sudo_reauth_title
    RedmineSaml.saml_sudo_reauth_title.presence || l(:label_saml_sudo_reauth_required)
  end

  def saml_sudo_reauth_text
    RedmineSaml.saml_sudo_reauth_text.presence || l(:text_saml_sudo_reauth_info)
  end

  def saml_sudo_reauth_button_label
    RedmineSaml.saml_sudo_reauth_button_label.presence || l(:button_saml_sudo_reauth)
  end
end
