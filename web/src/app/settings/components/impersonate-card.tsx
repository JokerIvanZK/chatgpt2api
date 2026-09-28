"use client";

import { useState } from "react";
import { Fingerprint, LoaderCircle, Save } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { useSettingsStore } from "../store";

// 2026-09 实测：同一代理下 surf 的 Chrome 系伪装请求 chatgpt.com 首页
// 一律 403 Cloudflare challenge，以下 Firefox 系全部 200。
const PRESETS = [
  { value: "firefox", label: "Firefox 148 · Windows（推荐）" },
  { value: "mac-firefox", label: "Firefox 148 · macOS" },
  { value: "linux-firefox", label: "Firefox 148 · Linux" },
  { value: "android-firefox", label: "Firefox 148 · Android" },
  { value: "ios-firefox", label: "Firefox 148 · iOS" },
  { value: "chrome110", label: "Chrome 110 · Windows" },
  { value: "chrome117", label: "Chrome 117 · Windows" },
  { value: "opera91", label: "Opera 91 · Windows" },
] as const;

const CUSTOM_OPTION = "__custom__";
const DEFAULT_OPTION = "__default__";

export function ImpersonateCard() {
  const [customMode, setCustomMode] = useState(false);
  const [customValue, setCustomValue] = useState("");
  const config = useSettingsStore((state) => state.config);
  const isLoadingConfig = useSettingsStore((state) => state.isLoadingConfig);
  const isSavingConfig = useSettingsStore((state) => state.isSavingConfig);
  const setImpersonate = useSettingsStore((state) => state.setImpersonate);
  const saveConfig = useSettingsStore((state) => state.saveConfig);

  const impersonate = (config?.impersonate ?? "").trim();
  const isPreset = PRESETS.some((item) => item.value === impersonate);
  const isCustomValue = impersonate !== "" && !isPreset;

  const selectValue = customMode || isCustomValue
    ? CUSTOM_OPTION
    : impersonate === ""
      ? DEFAULT_OPTION
      : impersonate;

  const handleSelect = (value: string) => {
    if (value === CUSTOM_OPTION) {
      setCustomValue(isCustomValue ? impersonate : "");
      setCustomMode(true);
      return;
    }
    setCustomMode(false);
    setImpersonate(value === DEFAULT_OPTION ? "" : value);
  };

  const handleSave = async () => {
    if (customMode) {
      setImpersonate(customValue.trim());
    }
    await saveConfig();
  };

  return (
    <Card>
      <CardContent className="space-y-6 p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-xl bg-stone-100">
              <Fingerprint className="size-5 text-stone-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight">浏览器伪装</h2>
              <p className="text-sm text-stone-500">
                每个账号默认由指纹池自动分配并保持粘性（7 天有效，命中 Cloudflare
                挑战自动换下一个）；这里选择具体变体可将全部账号固定为该 TLS 指纹。
              </p>
            </div>
          </div>
          <Badge
            variant={impersonate ? "success" : "secondary"}
            className="w-fit rounded-md px-2.5 py-1"
          >
            {impersonate ? impersonate : "默认 (firefox)"}
          </Badge>
        </div>

        {isLoadingConfig ? (
          <div className="flex items-center justify-center py-10">
            <LoaderCircle className="size-5 animate-spin text-stone-400" />
          </div>
        ) : (
          <>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">伪装配置</label>
              <Select value={selectValue} onValueChange={handleSelect}>
                <SelectTrigger id="settings-impersonate" className="h-11 rounded-xl border-stone-200 bg-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={DEFAULT_OPTION}>跟随默认（firefox）</SelectItem>
                  {PRESETS.map((item) => (
                    <SelectItem key={item.value} value={item.value}>
                      {item.label}
                    </SelectItem>
                  ))}
                  <SelectItem value={CUSTOM_OPTION}>自定义…</SelectItem>
                </SelectContent>
              </Select>
              {customMode || isCustomValue ? (
                <div className="space-y-2 pt-1">
                  <Input
                    value={customMode ? customValue : impersonate}
                    onChange={(event) => {
                      if (customMode) {
                        setCustomValue(event.target.value);
                      } else {
                        setImpersonate(event.target.value);
                      }
                    }}
                    placeholder="例如 mac-firefox、chrome145 等自定义 profile"
                    className="h-11 rounded-xl border-stone-200 bg-white"
                  />
                  <p className="text-sm text-stone-500">
                    自定义值按关键字匹配：含 firefox 走 Firefox 指纹，含 android / ios / mac /
                    linux 选择对应平台，其余按 Windows Chrome 处理（该指纹目前会被挑战）。
                    单个账号也可以在账号 fp 里单独指定，优先级高于全局设置。
                  </p>
                </div>
              ) : (
                <p className="text-sm text-stone-500">
                  留空（跟随默认）时由指纹池按账号哈希自动分配。选择某个具体变体会把所有
                  账号固定为该 TLS 指纹（设备身份仍各自独立）；也可选「自定义…」。单个账号在
                  fp 里手工指定的值优先级最高。
                </p>
              )}
            </div>

            <div className="flex justify-end gap-2">
              <Button
                className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
                onClick={() => void handleSave()}
                disabled={isSavingConfig}
              >
                {isSavingConfig ? <LoaderCircle className="size-4 animate-spin" /> : <Save className="size-4" />}
                保存配置
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
