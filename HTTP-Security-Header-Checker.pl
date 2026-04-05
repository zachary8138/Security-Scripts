#!/usr/bin/perl
#
# Security Header Checker -- Check an HTTPS (or HTTP) URL for common security
# response headers (HSTS, CSP, X-Frame-Options, etc.), flag missing recommended
# ones, and optionally emit JSON for scripting.
#
# Usage:  perl Secure_header_check.pl -u <url> [--json] [-v] [-t seconds]
# Example: perl Secure_header_check.pl -u https://example.com
# Help:    perl Secure_header_check.pl --help
#
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request;
use Getopt::Long;
use Term::ANSIColor;
use JSON;

# Configuration
my $url = "";
my $verbose = 0;
my $timeout = 10;
my $json_output = 0;
my $method = 'HEAD';

GetOptions(
    'url|u=s' => \$url,
    'verbose|v' => \$verbose,
    'timeout|t=i' => \$timeout,
    'json' => \$json_output,
    'help|h' => sub { print_help(); exit 0; }
);

if (!$url) {
    print_help();
    exit 1;
}

# Ensure URL has scheme
if ($url !~ /^https?:\/\//) {
    $url = "https://$url";
}

my $ua = LWP::UserAgent->new;
$ua->timeout($timeout);
$ua->max_redirect(5);
$ua->agent('Mozilla/5.0 SecurityScanner/1.0');

# Security headers
my %security_headers = (
    'Strict-Transport-Security' => { name => 'HSTS', recommended => 1 },
    'X-Frame-Options' => { name => 'X-Frame-Options', recommended => 1 },
    'X-Content-Type-Options' => { name => 'X-Content-Type-Options', recommended => 1 },
    'Content-Security-Policy' => { name => 'CSP', recommended => 1 },
    'X-XSS-Protection' => { name => 'X-XSS-Protection', recommended => 0 },
    'Referrer-Policy' => { name => 'Referrer-Policy', recommended => 1 },
    'Permissions-Policy' => { name => 'Permissions-Policy', recommended => 0 }
);

my $response = make_request($ua, $url, $method);

if (!$response->is_success && $method eq 'HEAD') {
    $response = make_request($ua, $url, 'GET');
}

if (!$response->is_success) {
    print "Error: " . $response->status_line . "\n";
    exit 2;
}

my ($results, $found_count, $recommended_count, $missing_recommended) = analyze_headers($response);

# JSON output mode
if ($json_output) {
    my %report = (
        target => $url,
        status => $response->status_line,
        results => $results,
        summary => {
            found => $found_count,
            missing_recommended => $missing_recommended
        }
    );
    print to_json(\%report, { pretty => 1 });
    exit($missing_recommended > 0 ? 1 : 0);
}

# Human-readable output
print color('bold') . "=" x 60 . "\nSecurity Header Check\n" . "=" x 60 . color('reset') . "\n";
print "Target: " . color('cyan') . $url . color('reset') . "\n\n";

print_results($results, $response);

print "\nSummary: ";
print "$found_count headers found";
print " (" . ($missing_recommended > 0 ? color('red') . "Missing $missing_recommended recommended" . color('reset') : "All recommended present") . ")\n";

exit($missing_recommended > 0 ? 1 : 0);

# ---------------- FUNCTIONS ----------------

sub make_request {
    my ($ua, $url, $method) = @_;
    my $req = HTTP::Request->new($method => $url);
    return $ua->request($req);
}

sub analyze_headers {
    my ($response) = @_;
    my @results;
    my $found = 0;
    my $recommended_found = 0;
    my $total_recommended = scalar(grep { $security_headers{$_}->{recommended} } keys %security_headers);

    foreach my $header (keys %security_headers) {
        my $value = $response->header($header);
        my $recommended = $security_headers{$header}->{recommended};

        my %entry = (
            header => $header,
            value => $value // "MISSING",
            recommended => $recommended,
            issues => []
        );

        if ($value) {
            $found++;
            $recommended_found++ if $recommended;

            # HSTS validation
            if ($header eq 'Strict-Transport-Security') {
                if ($value !~ /max-age=\d+/) {
                    push @{$entry{issues}}, "Missing max-age";
                }
            }
        }

        push @results, \%entry;
    }

    my $missing_recommended = $total_recommended - $recommended_found;
    return (\@results, $found, $recommended_found, $missing_recommended);
}

sub print_results {
    my ($results, $response) = @_;

    my $final_url = $response->request->uri->as_string;
    print "Final URL: " . color('cyan') . $final_url . color('reset') . "\n\n";

    print color('bold') . "Headers:\n" . color('reset');

    foreach my $r (@$results) {
        if ($r->{value} ne "MISSING") {
            print color('green') . "✓ " . color('reset') . "$r->{header}: $r->{value}\n";
        } elsif ($r->{recommended}) {
            print color('red') . "✗ $r->{header}: MISSING\n" . color('reset');
        } elsif ($verbose) {
            print color('yellow') . "○ $r->{header}: Not set\n" . color('reset');
        }

        if (@{$r->{issues}}) {
            print color('yellow') . "  ⚠ " . join(", ", @{$r->{issues}}) . "\n" . color('reset');
        }
    }
}

sub print_help {
    print <<HELP;
Security Header Checker

Usage:
  $0 -u <url> [options]

Options:
  -u, --url        Target URL
  -v, --verbose    Verbose output
  -t, --timeout    Timeout (default 10)
  --json           Output JSON
  -h, --help       Show help

Examples:
  $0 -u https://example.com
  $0 -u example.com --json
HELP
}
