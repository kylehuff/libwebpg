#include <emscripten/bind.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(my_class_example) {
    class_<webpg>("webpg")
        .constructor()
        .function("get_webpg_status", &webpg::get_webpg_status)
        .function("gnupghome", &webpg::gpgGetHomeDir)
        ;

    class_<Json::Value>("value")
        .constructor<const char>()
        ;
}
