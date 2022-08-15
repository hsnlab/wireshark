#!/bin/bash

# Convenience script to collect required deps for
# building HTTP/3 dissector

NGHTTP3_VERSION=0.6.0

install_nghttp3() {
    if [ "$NGHTTP3_VERSION" -a ! -f nghttp3-$NGHTTP3_VERSION-done ] ; then
        echo "Downloading, building, and installing nghttp3:"
        [ -f nghttp3-$NGHTTP3_VERSION.tar.xz ] || curl -L -O https://github.com/ngtcp2/nghttp3/releases/download/v$NGHTTP3_VERSION/nghttp3-$NGHTTP3_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat nghttp3-$NGHTTP3_VERSION.tar.xz | tar xf - || exit 1
        cd nghttp3-$NGHTTP3_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --enable-lib-only || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch nghttp3-$NGHTTP3_VERSION-done
    fi
}

uninstall_nghttp3() {
    if [ ! -z "$installed_nghttp3_version" ] ; then
        echo "Uninstalling nghttp3:"
        cd nghttp3-$installed_nghttp3_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm nghttp3-$installed_nghttp3_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf nghttp3-$installed_nghttp3_version
            rm -rf nghttp3-$installed_nghttp3_version.tar.xz
        fi

        installed_nghttp3_version=""
    fi
}

install_all() {

    if [ ! -z "$installed_nghttp3_version" -a \
              "$installed_nghttp3_version" != "$NGHTTP3_VERSION" ] ; then
        echo "Installed nghttp3 version is $installed_nghttp3_version"
        if [ -z "$NGHTTP3_VERSION" ] ; then
            echo "nghttp3 is not requested"
        else
            echo "Requested nghttp3 version is $NGHTTP3_VERSION"
        fi
        uninstall_nghttp3 -r
    fi

    install_nghttp3
}

uninstall_all() {

    if [ -d "${MACOSX_SUPPORT_LIBS}" ]
    then
        cd "${MACOSX_SUPPORT_LIBS}"

        uninstall_nghttp3
    fi
}

#
# Do we have permission to write in /usr/local?
#
# If so, assume we have permission to write in its subdirectories.
# (If that's not the case, this test needs to check the subdirectories
# as well.)
#
# If not, do "make install", "make uninstall", "ninja install",
# "ninja uninstall", the removes for dependencies that don't support
# "make uninstall" or "ninja uninstall", the renames of [g]libtool*,
# and the writing of a libffi .pc file with sudo.
#
if [ -w /usr/local ]
then
    DO_MAKE_INSTALL="make install"
    DO_MAKE_UNINSTALL="make uninstall"
    DO_NINJA_INSTALL="ninja -C _build install"
    DO_NINJA_UNINSTALL="ninja -C _build uninstall"
    DO_TEE_TO_PC_FILE="tee"
    DO_RM="rm"
    DO_MV="mv"
else
    DO_MAKE_INSTALL="sudo make install"
    DO_MAKE_UNINSTALL="sudo make uninstall"
    DO_NINJA_INSTALL="sudo ninja -C _build install"
    DO_NINJA_UNINSTALL="sudo ninja -C _build uninstall"
    DO_TEE_TO_PC_FILE="sudo tee"
    DO_RM="sudo rm"
    DO_MV="sudo mv"
fi

topdir=`git rev-parse --show-toplevel`
cd $topdir


# Preference of the support libraries directory:
#   ${MACOSX_SUPPORT_LIBS}
#   ../macosx-support-libs
#   ./macosx-support-libs (default if none exists)
if [ ! -d "${MACOSX_SUPPORT_LIBS}" ]; then
  unset MACOSX_SUPPORT_LIBS
fi
if [ -d ../macosx-support-libs ]; then
  MACOSX_SUPPORT_LIBS=${MACOSX_SUPPORT_LIBS-../macosx-support-libs}
else
  MACOSX_SUPPORT_LIBS=${MACOSX_SUPPORT_LIBS-./macosx-support-libs}
fi

#
#
# If we have SDKs available, the default target OS is the major version
# of the one we're running; get that and strip off the third component
# if present.
#
for i in /Developer/SDKs \
    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
    /Library/Developer/CommandLineTools/SDKs
do
    if [ -d "$i" ]
    then
        min_osx_target=`sw_vers -productVersion | sed 's/\([0-9]*\)\.\([0-9]*\)\.[0-9]*/\1.\2/'`
        break
    fi
done

#
# Parse command-line flags:
#
# -h - print help.
# -t <target> - build libraries so that they'll work on the specified
# version of macOS and later versions.
# -u - do an uninstall.
# -n - download all packages, but don't build or install.
#

no_build=false

while getopts ht:un name
do
    case $name in
    u)
        do_uninstall=yes
        ;;
    n)
        no_build=true
        ;;
    t)
        min_osx_target="$OPTARG"
        ;;
    h|?)
        echo "Usage: macos-setup.sh [ -t <target> ] [ -u ] [ -n ]" 1>&1
        exit 0
        ;;
    esac
done

#
# Get the version numbers of installed packages, if any.
#
if [ -d "${MACOSX_SUPPORT_LIBS}" ]
then
    cd "${MACOSX_SUPPORT_LIBS}"

    installed_nghttp3_version=`ls nghttp3-*-done 2>/dev/null | sed 's/nghttp3-\(.*\)-done/\1/'`

    cd $topdir
fi

if [ "$do_uninstall" = "yes" ]
then
    uninstall_all
    exit 0
fi

#
# Configure scripts tend to set CFLAGS and CXXFLAGS to "-g -O2" if
# invoked without CFLAGS or CXXFLAGS being set in the environment.
#
# However, we *are* setting them in the environment, for our own
# nefarious purposes, so start them out as "-g -O2".
#
CFLAGS="-g -O2"
CXXFLAGS="-g -O2"

# if no make options are present, set default options
if [ -z "$MAKE_BUILD_OPTS" ] ; then
    # by default use 1.5x number of cores for parallel build
    MAKE_BUILD_OPTS="-j $(( $(sysctl -n hw.logicalcpu) * 3 / 2))"
fi

#
# If we have a target release, look for the oldest SDK that's for an
# OS equal to or later than that one, and build libraries against it
# rather than against the headers and, more importantly, libraries
# that come with the OS, so that we don't end up with support libraries
# that only work on the OS version on which we built them, not earlier
# versions of the same release, or earlier releases if the minimum is
# earlier.
#
if [ ! -z "$min_osx_target" ]
then
    #
    # Get the major and minor version of the target release.
    # We assume it'll be a while before there's a macOS 100. :-)
    #
    case "$min_osx_target" in

    [1-9][0-9].*)
        #
        # major.minor.
        #
        min_osx_target_major=`echo "$min_osx_target" | sed -n 's/\([1-9][0-9]*\)\..*/\1/p'`
        min_osx_target_minor=`echo "$min_osx_target" | sed -n 's/[1-9][0-9]*\.\(.*\)/\1/p'`
        ;;

    [1-9][0-9])
        #
        # Just a major version number was specified; make the minor
        # version 0.
        #
        min_osx_target_major="$min_osx_target"
        min_osx_target_minor=0
        ;;

    *)
        echo "macosx-setup.sh: Invalid target release $min_osx_target" 1>&2
        exit 1
        ;;
    esac

    #
    # Search each directory that might contain SDKs.
    #
    sdkpath=""
    for sdksdir in /Developer/SDKs \
        /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
        /Library/Developer/CommandLineTools/SDKs
    do
        #
        # Get a list of all the SDKs.
        #
        if ! test -d "$sdksdir"
        then
            #
            # There is no directory with that name.
            # Move on to the next one in the list, if any.
            #
            continue
        fi

        #
        # Get a list of all the SDKs in that directory, if any.
        # We assume it'll be a while before there's a macOS 100. :-)
        #
        sdklist=`(cd "$sdksdir"; ls -d MacOSX[1-9][0-9].[0-9]*.sdk 2>/dev/null)`

        for sdk in $sdklist
        do
            #
            # Get the major and minor version for this SDK.
            #
            sdk_major=`echo "$sdk" | sed -n 's/MacOSX\([1-9][0-9]*\)\..*\.sdk/\1/p'`
            sdk_minor=`echo "$sdk" | sed -n 's/MacOSX[1-9][0-9]*\.\(.*\)\.sdk/\1/p'`

            #
            # Is it for the deployment target or some later release?
            # Starting with major 11, the minor version no longer matters.
            #
            if test "$sdk_major" -gt "$min_osx_target_major" -o \
                \( "$sdk_major" -eq "$min_osx_target_major" -a \
                \( "$sdk_major" -ge 11 -o \
                   "$sdk_minor" -ge "$min_osx_target_minor" \) \)
            then
                #
                # Yes, use it.
                #
                sdkpath="$sdksdir/$sdk"
                break 2
            fi
        done
    done

    if [ -z "$sdkpath" ]
    then
        echo "macos-setup.sh: Couldn't find an SDK for macOS $min_osx_target or later" 1>&2
        exit 1
    fi

    SDKPATH="$sdkpath"
    echo "Using the $sdk_major.$sdk_minor SDK"

    #
    # Make sure there are links to /usr/local/include and /usr/local/lib
    # in the SDK's usr/local.
    #
    if [ ! -e $SDKPATH/usr/local/include ]
    then
        if [ ! -d $SDKPATH/usr/local ]
        then
            sudo mkdir $SDKPATH/usr/local
        fi
        sudo ln -s /usr/local/include $SDKPATH/usr/local/include
    fi
    if [ ! -e $SDKPATH/usr/local/lib ]
    then
        if [ ! -d $SDKPATH/usr/local ]
        then
            sudo mkdir $SDKPATH/usr/local
        fi
        sudo ln -s /usr/local/lib $SDKPATH/usr/local/lib
    fi

    #
    # Set the minimum OS version for which to build to the specified
    # minimum target OS version, so we don't, for example, end up using
    # linker features supported by the OS verson on which we're building
    # but not by the target version.
    #
    VERSION_MIN_FLAGS="-mmacosx-version-min=$min_osx_target"

    #
    # Compile and link against the SDK.
    #
    SDKFLAGS="-isysroot $SDKPATH"

fi

export CFLAGS
export CXXFLAGS

#
# You need Xcode or the command-line tools installed to get the compilers (xcrun checks both).
#
 if [ ! -x /usr/bin/xcrun ]; then
    echo "Please install Xcode (app or command line) first (should be available on DVD or from the Mac App Store)."
    exit 1
fi

if [ "$QT_VERSION" ]; then
    #
    # We need Xcode, not just the command-line tools, installed to build
    # Qt.
    #
    # At least with Xcode 8, /usr/bin/xcodebuild --help fails if only
    # the command-line tools are installed and succeeds if Xcode is
    # installed.  Unfortunately, it fails *with* Xcode 3, but
    # /usr/bin/xcodebuild -version works with that and with Xcode 8.
    # Hopefully it fails with only the command-line tools installed.
    #
    if /usr/bin/xcodebuild -version >/dev/null 2>&1; then
        :
    elif qmake --version >/dev/null 2>&1; then
        :
    else
        echo "Please install Xcode first (should be available on DVD or from the Mac App Store)."
        echo "The command-line build tools are not sufficient to build Qt."
        echo "Alternatively build QT according to: https://gist.github.com/shoogle/750a330c851bd1a924dfe1346b0b4a08#:~:text=MacOS%2FQt%5C%20Creator-,Go%20to%20Qt%20Creator%20%3E%20Preferences%20%3E%20Build%20%26%20Run%20%3E%20Kits,for%20both%20compilers%2C%20not%20gcc%20."
        exit 1
    fi
fi

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

#
# Do all the downloads and untarring in a subdirectory, so all that
# stuff can be removed once we've installed the support libraries.

if [ ! -d "${MACOSX_SUPPORT_LIBS}" ]
then
    mkdir "${MACOSX_SUPPORT_LIBS}" || exit 1
fi
cd "${MACOSX_SUPPORT_LIBS}"

install_all

echo ""

#
# Indicate what paths to use for pkg-config and cmake.
#
pkg_config_path=/usr/local/lib/pkgconfig
if [ "$QT_VERSION" ]; then
    qt_base_path=$HOME/Qt$QT_VERSION/$QT_VERSION/clang_64
    pkg_config_path="$pkg_config_path":"$qt_base_path/lib/pkgconfig"
    CMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH":"$qt_base_path/lib/cmake"
fi

if $no_build; then
    echo "All required dependencies downloaded. Run without -n to install them."
    exit 0
fi

echo "You are now prepared to build Wireshark."
echo
echo "To build:"
echo
echo "export PKG_CONFIG_PATH=$pkg_config_path"
echo "export CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH"
echo "export PATH=$PATH:$qt_base_path/bin"
echo
echo "mkdir build; cd build"
if [ ! -z "$NINJA_VERSION" ]; then
    echo "cmake -G Ninja .."
    echo "ninja wireshark_app_bundle logray_app_bundle # (Modify as needed)"
    echo "ninja install/strip"
else
    echo "cmake .."
    echo "make $MAKE_BUILD_OPTS wireshark_app_bundle logray_app_bundle # (Modify as needed)"
    echo "make install/strip"
fi
echo
echo "Make sure you are allowed capture access to the network devices"
echo "See: https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup/CapturePrivileges"
echo

exit 0
