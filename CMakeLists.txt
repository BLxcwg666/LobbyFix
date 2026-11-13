cmake_minimum_required(VERSION 3.20)

project(LobbyFix LANGUAGES CXX)

set(MMSOURCE_DIR "$ENV{MMSOURCE_DIR}" CACHE PATH
	"Metamod:Source source tree (the directory containing core/ISmmPlugin.h). Leave empty to fetch it automatically.")
set(MMSOURCE_GIT_TAG "1.12.0.1229" CACHE STRING
	"Metamod:Source tag to fetch when MMSOURCE_DIR is empty")

if(NOT MMSOURCE_DIR)
	include(FetchContent)
	FetchContent_Declare(metamod_source
		GIT_REPOSITORY https://github.com/alliedmodders/metamod-source.git
		GIT_TAG ${MMSOURCE_GIT_TAG}
		GIT_SHALLOW TRUE
		GIT_SUBMODULES ""
	)
	FetchContent_MakeAvailable(metamod_source)
	set(MMSOURCE_DIR "${metamod_source_SOURCE_DIR}")
endif()

set(MMSOURCE_CORE "${MMSOURCE_DIR}/core")
if(NOT EXISTS "${MMSOURCE_CORE}/ISmmPlugin.h" OR NOT EXISTS "${MMSOURCE_CORE}/sourcehook/sourcehook.h")
	message(FATAL_ERROR "MMSOURCE_DIR='${MMSOURCE_DIR}' is not a Metamod:Source source tree")
endif()

if(WIN32)
	# ISmmPlugin is consumed through its vtable, so the plugin must use the same C++ ABI as metamod.2.csgo.dll.
	if(NOT MSVC)
		message(FATAL_ERROR "Windows builds require MSVC or clang-cl (MinGW's vtable layout is incompatible with Metamod)")
	endif()
	if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
		message(FATAL_ERROR "CS:GO legacy srcds is 32-bit: use the x86 toolchain (e.g. -A Win32, or CLion's Visual Studio toolchain with Architecture = x86)")
	endif()
elseif(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
	message(FATAL_ERROR "Only Windows and Linux are supported")
endif()

add_library(lobbyfix MODULE src/lobbyfix.cpp)

# Metamod loads "addons/lobbyfix/lobbyfix" + .dll/.so, so no "lib" prefix.
set_target_properties(lobbyfix PROPERTIES
	PREFIX ""
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
	CXX_EXTENSIONS OFF
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN ON
)

target_include_directories(lobbyfix SYSTEM PRIVATE
	"${MMSOURCE_CORE}"
	"${MMSOURCE_CORE}/sourcehook"
)

string(TIMESTAMP LOBBYFIX_BUILD_DATE "%Y-%m-%d")
target_compile_definitions(lobbyfix PRIVATE
	META_NO_HL2SDK
	"LOBBYFIX_DATE=\"${LOBBYFIX_BUILD_DATE}\""
)

if(MSVC)
	set_property(TARGET lobbyfix PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	target_compile_definitions(lobbyfix PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
	target_compile_options(lobbyfix PRIVATE /W3)
else()
	include(CheckLinkerFlag)
	check_linker_flag(CXX "-nostdlib++" LOBBYFIX_HAVE_NOSTDLIBXX)

	set(LOBBYFIX_EXPORTS_MAP "${CMAKE_CURRENT_SOURCE_DIR}/src/exports.map")

	# The source provides its own __cxa_pure_virtual / operator delete so it can link without libstdc++;
	# RTTI, exceptions and guarded statics are disabled because they would pull in libsupc++ symbols.
	target_compile_options(lobbyfix PRIVATE
		-m32
		-fno-exceptions
		-fno-rtti
		-fno-threadsafe-statics
		-Wall
	)
	target_link_options(lobbyfix PRIVATE
		-m32
		-static-libgcc
		"LINKER:--version-script=${LOBBYFIX_EXPORTS_MAP}"
		"LINKER:--no-undefined"
	)
	if(LOBBYFIX_HAVE_NOSTDLIBXX)
		target_link_options(lobbyfix PRIVATE -nostdlib++)
	else()
		target_link_options(lobbyfix PRIVATE -static-libstdc++)
	endif()
	set_property(TARGET lobbyfix APPEND PROPERTY LINK_DEPENDS "${LOBBYFIX_EXPORTS_MAP}")
endif()

# `cmake --install <build> --prefix <csgo dir>` produces the layout Metamod expects.
install(TARGETS lobbyfix LIBRARY DESTINATION addons/lobbyfix)
install(FILES lobbyfix.vdf DESTINATION addons/metamod)
