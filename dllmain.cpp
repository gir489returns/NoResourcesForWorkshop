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
                    auto aob_DoesHaveResources = PatternScanner::Scan("90 8B C7 4C 8D 9C 24 C0 00 00 00", "aob_DoesHaveResources").GetAt(1).To<PVOID>();
                    DWORD oldProtect;
                    if (aob_DoesHaveResources)
                    {
                        VirtualProtect(aob_DoesHaveResources, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *(PSHORT)aob_DoesHaveResources = 0xC0FF;
                        VirtualProtect(aob_DoesHaveResources, 2, oldProtect, &oldProtect);
                    }

                    auto aob_GetResourcesTotal = PatternScanner::Scan("0F 84 EA 01 00 00 48 8B 01 48 ", "aob_GetResourcesTotal").To<PVOID>();
                    if (aob_GetResourcesTotal)
                    {
                        VirtualProtect(aob_GetResourcesTotal, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *(PSHORT)aob_GetResourcesTotal = 0xE990;
                        VirtualProtect(aob_GetResourcesTotal, 2, oldProtect, &oldProtect);
                    }
                }

                if (config["NoResourcesForWorkshop"]["IgnoreCraftingMaterials"] == "1")
                {
                    auto noMats = PatternScanner::Scan("0F 84 ? ? ? ? 8B ? 10 C5 D0", "noMats").GetAt(6).To<PCHAR>();
                    DWORD oldProtect;
                    if (noMats)
                    {
                        VirtualProtect(noMats, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *(PCHAR)noMats = 0x31;
                        *(PCHAR)(noMats+1) = 0xF6;
                        *(PCHAR)(noMats+2) = 0x90;
                        VirtualProtect(noMats, 3, oldProtect, &oldProtect);
                    }
                }

                if (config["NoResourcesForWorkshop"]["InfiniteVehicleBoost"] == "1")
                {
                    auto aob_Bbbbbbboost = PatternScanner::Scan("74 ? 48 39 35 ? ? ? ? 74 ? 83 3D", "aob_Bbbbbbboost").To<PCHAR>();
                    DWORD oldProtect;
                    if (aob_Bbbbbbboost)
                    {
                        VirtualProtect(aob_Bbbbbbboost, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *aob_Bbbbbbboost = 0x7C;
                        VirtualProtect(aob_Bbbbbbboost, 1, oldProtect, &oldProtect);
                    }
                }

                if (config["NoResourcesForWorkshop"]["NoResourcesForResearch"] == "1")
                {
                    auto aob_NoresourcesForResearch = PatternScanner::Scan("41 0F AF C8 49 8B 56", "aob_NoresourcesForResearch").To<PDWORD>();
                    DWORD oldProtect;
                    if (aob_NoresourcesForResearch)
                    {
                        VirtualProtect(aob_NoresourcesForResearch, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *aob_NoresourcesForResearch = 0x90CC8B41;
                        VirtualProtect(aob_NoresourcesForResearch, 4, oldProtect, &oldProtect);
                    }

                    auto aob_ResearchSkillCheck = PatternScanner::Scan("3B 43 ? 72 ? B0 ? 48 83 C4", "aob_ResearchSkillCheck").GetAt(3).To<PSHORT>();
                    if (aob_ResearchSkillCheck)
                    {
                        VirtualProtect(aob_ResearchSkillCheck, 2, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *aob_ResearchSkillCheck = 0x9090;
                        VirtualProtect(aob_ResearchSkillCheck, 2, oldProtect, &oldProtect);
                    }

                    auto aob_OtherResourcesForResearch = PatternScanner::Scan("E8 ? ? ? ? 8B E8 85 C0 75 ? 48 83 7F", "aob_OtherResourcesForResearch").GetCall().To<PCHAR>();
                    if (aob_OtherResourcesForResearch)
                    {
                        VirtualProtect(aob_OtherResourcesForResearch, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
                        *(PCHAR)aob_OtherResourcesForResearch = 0xB8;
                        *(PINT)(aob_OtherResourcesForResearch+1) = -1;
                        *(aob_OtherResourcesForResearch+5) = 0xC3;
                        VirtualProtect(aob_OtherResourcesForResearch, 6, oldProtect, &oldProtect);
                    }
                }

                ExitThread(0);
        }, nullptr, 0, nullptr);
    }
    return TRUE;
}

