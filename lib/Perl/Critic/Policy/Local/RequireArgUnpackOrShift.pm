package Perl::Critic::Policy::Local::RequireArgUnpackOrShift;

use strict;
use warnings;

our $VERSION = '0.01';

use Readonly;

use Perl::Critic::Utils qw<
  :booleans :characters :severities words_from_string
>;
use Perl::Critic::Policy::Subroutines::RequireArgUnpacking;

use base 'Perl::Critic::Policy';

Readonly::Scalar my $AT_ARG => q{@_};    ## no critic (InterpolationOfMetachars)
Readonly::Scalar my $DESC => qq{Always unpack $AT_ARG first};
Readonly::Scalar my $EXPL => [178];

my $rau = Perl::Critic::Policy::Subroutines::RequireArgUnpacking->new;

my @subroutines = (
    qw(
      _is_size_check
      _is_postfix_foreach
      _is_cast_of_array
      _is_cast_of_scalar
      _get_arg_symbols
      _magic_finder
      )
);

my @methods = (
    qw(
      supported_parameters
      default_severity
      default_themes
      applies_to
      _is_unpack
      _is_delegation
      )
);

{

    no strict 'refs';

    for (@subroutines) {
        my $sname = $_;
        *{ __PACKAGE__ . '::' . $sname } = sub {
            my $fq_sname = join( '::', ref($rau), $sname );
            return &{$fq_sname}(@_);
        };
    }

    for (@methods) {
        my $method = $_;
        *{ __PACKAGE__ . '::' . $method } = sub {
            my $self = shift;
            return $rau->$method(@_);
        };
    }

}

sub violates {
    my ( $self, $elem, undef ) = @_;
    warn "In OrShift version\n";

    # forward declaration?
    return if not $elem->block;

    my @statements = $elem->block->schildren;

    # empty sub?
    return if not @statements;

    # Don't apply policy to short subroutines

    # Should we instead be doing a find() for PPI::Statement
    # instances?  That is, should we count all statements instead of
    # just top-level statements?
    return if $self->{_short_subroutine_statements} >= @statements;

    # look for explicit dereferences of @_, including '$_[0]'
    # You may use "... = @_;" in the first paragraph of the sub
    # Don't descend into nested or anonymous subs

    my $state = 'unpacking';    # still in unpacking paragraph
    for my $statement (@statements) {

        # this picks up "my $self =- shift;" and "my $foo = shift // 'bar';"
        next
          if $statement =~ m{\$\w+\s*=\s*shift(\(\s*\@_\s*\))?;}
          or $statement =~ m{\$\w+\s*=\s*shift(\(\s*\@_\s*\))?\s?(//|\|\|)};

        my @magic = _get_arg_symbols($statement);

        my $saw_unpack = $FALSE;

      MAGIC:
        for my $magic (@magic) {

            # allow conditional checks on the size of @_
            my $size_check = _is_size_check($magic) || 0;
            next MAGIC if _is_size_check($magic);

            if ( 'unpacking' eq $state ) {
                if ( $self->_is_unpack($magic) ) {
                    $saw_unpack = $TRUE;
                    next MAGIC;
                }
            }

            # allow @$_[] construct in "... for ();"
            # Check for "print @$_[] for ()" construct (rt39601)
            next MAGIC
              if _is_cast_of_array($magic)
              and _is_postfix_foreach($magic);

            # allow $$_[], which is equivalent to $_->[] and not a use
            # of @_ at all.
            next MAGIC
              if _is_cast_of_scalar($magic);

            # allow delegation of the form "$self->SUPER::foo( @_ );"
            next MAGIC
              if $self->_is_delegation($magic);

            # If we make it this far, it is a violaton
            return $self->violation( $DESC, $EXPL, $elem );
        }
        if ( not $saw_unpack ) {
            $state = 'post_unpacking';
        }
    }
    return;    # OK
}

1;

