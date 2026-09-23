from ghintel.gitconfig import parse_git_config_text


def test_remote_roles_and_urls_are_parsed_without_includes() -> None:
    parsed = parse_git_config_text(
        '''
        [include]
            path = /outside/config
        [remote "origin"]
            url = git@github.com:Owner/Repository.git
            pushurl = ssh://git@github.com/Owner/Repository.git
        [remote "upstream"]
            url = https://github.com/Original/Project
        '''
    )
    assert len(parsed.remotes) == 3
    assert parsed.remotes[0].role.value == "origin"
    assert parsed.remotes[0].repository is not None
    assert parsed.remotes[0].repository.identity_key == "github.com/owner/repository"
    assert parsed.remotes[2].role.value == "upstream"
    assert any("ignored Git config include" in message for message in parsed.diagnostics)
