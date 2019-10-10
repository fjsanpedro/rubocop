# frozen_string_literal: true

RSpec.describe RuboCop::Cop::Security::Open, :config do
  subject(:cop) { described_class.new(config) }

  let(:cop_config) do
    { 'DisallowAll' => disallow_value }
  end

  shared_examples 'common offenses' do
    context 'with variable or method' do
      it 'registers an offense for open' do
        expect_offense(<<~RUBY)
          open(something)
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'registers an offense for Kernel.open' do
        expect_offense(<<~RUBY)
          Kernel.open(something)
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end

    context 'with mode argument' do
      it 'registers an offense for open' do
        expect_offense(<<~RUBY)
          open(something, "r")
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'registers an offense for Kernel.open' do
        expect_offense(<<~RUBY)
          Kernel.open(something, "r")
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end

    context 'with dynamic string that is not prefixed' do
      it 'registers an offense for open' do
        expect_offense(<<~'RUBY')
          open("#{foo}.txt")
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'registers an offense for Kernel.open' do
        expect_offense(<<~'RUBY')
          Kernel.open("#{foo}.txt")
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end

    context 'with string that starts with a pipe' do
      it 'registers an offense for open' do
        expect_offense(<<~'RUBY')
          open("| #{foo}")
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'registers an offense for Kernel.open' do
        expect_offense(<<~'RUBY')
          Kernel.open("| #{foo}")
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end

    context 'with no arguments' do
      it 'accepts open' do
        expect_no_offenses('open')
      end

      it 'registers an offense for Kernel.open' do
        expect_no_offenses('Kernel.open')
      end
    end

    it 'accepts open as variable' do
      expect_no_offenses('open = something')
    end

    it 'accepts File.open as method' do
      expect_no_offenses('File.open(something)')
    end
  end

  context 'when DisallowAll config option is disabled' do
    let(:disallow_value) { false }

    it_behaves_like 'common offenses'

    context 'with a literal string' do
      it 'accepts open' do
        expect_no_offenses('open("foo.txt")')
      end

      it 'accepts Kernel.open' do
        expect_no_offenses('Kernel.open("foo.txt")')
      end
    end

    context 'with string that has a prefixed interpolation' do
      it 'accepts open' do
        expect_no_offenses('open "prefix_#{foo}"')
      end

      it 'accepts Kernel.open' do
        expect_no_offenses('Kernel.open "prefix_#{foo}"')
      end
    end

    context 'with prefix string literal plus something' do
      it 'accepts open' do
        expect_no_offenses('open "prefix" + foo')
      end

      it 'accepts Kerenel.open' do
        expect_no_offenses('Kernel.open "prefix" + foo')
      end
    end

    context 'with a string that interpolates a literal' do
      it 'accepts open' do
        expect_no_offenses('open "foo#{2}.txt"')
      end

      it 'accepts Kernel.open' do
        expect_no_offenses('Kernel.open "foo#{2}.txt"')
      end
    end
  end

  context 'when DisallowAll config option is enabled' do
    let(:disallow_value) { true }

    it_behaves_like 'common offenses'

    context 'with a literal string' do
      it 'registers an offense for open' do
        expect_offense(<<~'RUBY')
          open("foo.txt")
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'registers an offense for Kernel.open' do
        expect_offense(<<~'RUBY')
          Kernel.open("foo.txt")
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end

    context 'with string that has a prefixed interpolation' do
      it 'registers an offense for open' do
        expect_offense(<<~'RUBY')
          open "prefix_#{foo}"
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'registers an offense for Kernel.open' do
        expect_offense(<<~'RUBY')
          Kernel.open "prefix_#{foo}"
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end

    context 'with prefix string literal plus something' do
      it 'accepts open' do
        expect_offense(<<~'RUBY')
          open "prefix" + foo
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'accepts Kerenel.open' do
        expect_offense(<<~'RUBY')
          Kernel.open "prefix" + foo
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end

    context 'with a string that interpolates a literal' do
      it 'accepts open' do
        expect_offense(<<~'RUBY')
          open "foo#{2}.txt"
          ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end

      it 'accepts Kernel.open' do
        expect_offense(<<~'RUBY')
          Kernel.open "foo#{2}.txt"
                 ^^^^ The use of `Kernel#open` is a serious security risk.
        RUBY
      end
    end
  end
end
