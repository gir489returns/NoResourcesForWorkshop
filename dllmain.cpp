// dllmain.cpp : Defines the entry point for the DLL application.
#include "PatternScanner.hpp"
#include <string>
#include "ini.h"

HANDLE main_thread{};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        static auto this_module = hModule;
        main_thread = CreateThread(nullptr, 0,
            [](PVOID) -> DWORD {

                std::ifstream stream("SFAE ASIL\\NoResourcesForWorkshop.ini");
                ini::File config = ini::load(stream);
                stream.close();

                if (config["NoResourcesForWorkshop"]["NoResources"] == "1")
                {
                    auto aob_DoesHaveResources = PatternScanner::Scan("90 8B C7 4C 8D 9C 24 C0 00 00 00").GetAt(1).To<PVOID>();
                    DWORD oldProtect;
                    if (aob_DoesHaveResources)
                    {
                        VirtualProtect(aob_DoesHaveResources, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *(PSHORT)aob_DoesHaveResources = 0xC0FF;
                        VirtualProtect(aob_DoesHaveResources, 2, oldProtect, &oldProtect);
                    }
                    else
                    {
                        MessageBox(NULL, L"aob_DoesHaveResources signature failed.", L"NoResourcesForWorkshop ERROR", MB_ICONERROR | MB_OK);
                    }

                    auto aob_GetResourcesTotal = PatternScanner::Scan("0F 84 EA 01 00 00 48 8B 01 48 ").To<PVOID>();
                    if (aob_GetResourcesTotal)
                    {
                        VirtualProtect(aob_GetResourcesTotal, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *(PSHORT)aob_GetResourcesTotal = 0xC0FF;
                        VirtualProtect(aob_GetResourcesTotal, 2, oldProtect, &oldProtect);
                    }
                    else
                    {
                        MessageBox(NULL, L"aob_GetResourcesTotal signature failed.", L"NoResourcesForWorkshop ERROR", MB_ICONERROR | MB_OK);
                    }
                }

                if (config["NoResourcesForWorkshop"]["IgnoreCraftingMaterials"] == "1")
                {
                    auto noMats = PatternScanner::Scan("0F 84 ? ? ? ? 8B ? 10 C5 D0").GetAt(6).To<PCHAR>();
                    DWORD oldProtect;
                    if (noMats)
                    {
                        VirtualProtect(noMats, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *(PCHAR)noMats = 0x31;
                        *(PCHAR)(noMats+1) = 0xF6;
                        *(PCHAR)(noMats+2) = 0x90;
                        VirtualProtect(noMats, 3, oldProtect, &oldProtect);
                    }
                    else
                    {
                        MessageBox(NULL, L"IgnoreCraftingMaterials signature failed.", L"NoResourcesForWorkshop ERROR", MB_ICONERROR | MB_OK);
                    }
                }

                if (config["NoResourcesForWorkshop"]["InfiniteVehicleBoost"] == "1")
                {
                    auto aob_Bbbbbbboost = PatternScanner::Scan("74 ? 48 39 35 ? ? ? ? 74 ? 83 3D").To<PCHAR>();
                    DWORD oldProtect;
                    if (aob_Bbbbbbboost)
                    {
                        VirtualProtect(aob_Bbbbbbboost, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *aob_Bbbbbbboost = 0x7C;
                        VirtualProtect(aob_Bbbbbbboost, 1, oldProtect, &oldProtect);
                    }
                    else
                    {
                        MessageBox(NULL, L"InfiniteVehicleBoost signature failed.", L"NoResourcesForWorkshop ERROR", MB_ICONERROR | MB_OK);
                    }
                }
                ExitThread(0);
        }, nullptr, 0, nullptr);
    }
    return TRUE;
}

