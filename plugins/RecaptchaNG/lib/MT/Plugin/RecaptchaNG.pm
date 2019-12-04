package MT::Plugin::RecaptchaNG;

use strict;
use warnings;
use utf8;

use File::Basename qw(basename dirname);
use MT::Util qw();

sub component {
    __PACKAGE__ =~ m/::([^:]+)\z/;
}

sub plugin {
    MT->component( component() );
}

sub error {
    my ($app) = @_;

    $app->show_error( { status => 400 } );
    $app->mode('recaptchang_400error');
    $app->{requires_login} = 0;
    $app->{vtbl}{recaptchang_400error} = sub {
        $app->show_error(
            {   status => 400,
                error =>
                    plugin()->translate('Failed to verify reCAPTCHA token.'),
            }
        );
    }
}

sub init_request {
    my ( $cb, $app ) = @_;

    my $id = eval { $app->id }
        or return 1;

    my $config = eval {
        MT::Util::from_json( plugin()->get_config_value('recaptchang_apps') );
    }
        or return 1;

    return 1
        unless ref( $config->{$id} ) eq 'HASH'
        && $config->{$id}{ $app->mode };

    my $token
        = $app->param(
        plugin()->get_config_value('recaptchang_parameter_key') )
        or return error($app);

    my $ua = MT->new_ua( { timeout => 10 } );
    if ( !$ua ) {
        return error($app);
    }

    my $secret = plugin()->get_config_value('recaptchang_secret');

    my $res = $ua->post(
        "https://www.google.com/recaptcha/api/siteverify",
        {   secret   => $secret,
            response => $token,
            remoteip => $app->remote_ip,
        }
    );

    return error($app) unless $res && $res->is_success;

    my $obj = MT::Util::from_json( $res->content );

    return error($app) unless $obj->{success};

    1;
}

sub template_source_recaptchang_system_config {
    my ( $cb, $app, $tmpl ) = @_;

    my %apps = map {
        map { $_ => 1 } keys %$_;
    } @{ MT::Component->registry('applications') };
    my @apps = sort grep { $_ ne 'plugin' } keys %apps;
    $$tmpl
        = qq{<mt:SetVar name="apps" value=@{[join(',', map { qq{"$_"} } @apps)]}/>}
        . $$tmpl;
}

1;
