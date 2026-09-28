"use client";

import { useEffect, useState } from "react";
import { Dices, LoaderCircle, Plus, Save, Trash2, Waves } from "lucide-react";

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

// 与后端 fingerprintPool 对齐:实测可通过 Cloudflare 的变体
const PROFILE_OPTIONS = ["firefox", "mac-firefox", "linux-firefox", "android-firefox", "ios-firefox"];

type PoolEntry = {
  label: string;
  impersonate: string;
  "oai-device-id"?: string;
  "oai-session-id"?: string;
};

function parsePool(raw: string | undefined): PoolEntry[] {
  const text = (raw ?? "").trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is PoolEntry => item && typeof item.impersonate === "string" && item.impersonate.trim() !== "",
    );
  } catch {
    return [];
  }
}

function randomUUID(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (ch) => {
    const random = (Math.random() * 16) | 0;
    return (ch === "x" ? random : (random & 0x3) | 0x8).toString(16);
  });
}

function makeRandomEntry(seq: number): PoolEntry {
  return {
    label: `随机 ${seq}`,
    impersonate: PROFILE_OPTIONS[Math.floor(Math.random() * PROFILE_OPTIONS.length)],
    "oai-device-id": randomUUID(),
    "oai-session-id": randomUUID(),
  };
}

export function FingerprintPoolCard() {
  const [entries, setEntries] = useState<PoolEntry[] | null>(null);
  const [batchCount, setBatchCount] = useState("10");
  const [manualProfile, setManualProfile] = useState(PROFILE_OPTIONS[0]);
  const [manualLabel, setManualLabel] = useState("");

  const config = useSettingsStore((state) => state.config);
  const isLoadingConfig = useSettingsStore((state) => state.isLoadingConfig);
  const isSavingConfig = useSettingsStore((state) => state.isSavingConfig);
  const setFingerprintPool = useSettingsStore((state) => state.setFingerprintPool);
  const saveConfig = useSettingsStore((state) => state.saveConfig);

  useEffect(() => {
    if (!isLoadingConfig && config && entries === null) {
      setEntries(parsePool(config.fingerprint_pool));
    }
  }, [isLoadingConfig, config, entries]);

  const current = entries ?? [];
  const nextSeq = current.filter((item) => item.label.startsWith("随机")).length + 1;

  const persist = (next: PoolEntry[]) => {
    setEntries(next);
    setFingerprintPool(next.length > 0 ? JSON.stringify(next) : "");
  };

  const handleSave = async () => {
    await saveConfig();
  };

  return (
    <Card>
      <CardContent className="space-y-6 p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-xl bg-stone-100">
              <Waves className="size-5 text-stone-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight">指纹池</h2>
              <p className="text-sm text-stone-500">
                账号按哈希绑定池中条目，7 天粘性，命中挑战自动换下一个。留空使用内置的 5
                个实测可用变体（每账号独立设备 ID）。
              </p>
            </div>
          </div>
          <Badge variant={current.length > 0 ? "success" : "secondary"} className="w-fit rounded-md px-2.5 py-1">
            {current.length > 0 ? `${current.length} 条` : "内置池"}
          </Badge>
        </div>

        {isLoadingConfig || entries === null ? (
          <div className="flex items-center justify-center py-10">
            <LoaderCircle className="size-5 animate-spin text-stone-400" />
          </div>
        ) : (
          <>
            {current.length > 0 ? (
              <div className="space-y-2">
                {current.map((item, index) => (
                  <div
                    key={`${item.impersonate}-${index}`}
                    className="flex items-center gap-3 rounded-xl border border-stone-200 bg-white px-4 py-2.5 text-sm"
                  >
                    <span className="w-24 shrink-0 truncate font-medium text-stone-700">{item.label || `#${index + 1}`}</span>
                    <span className="font-mono text-stone-600">{item.impersonate}</span>
                    <span className="flex-1 truncate font-mono text-xs text-stone-400">
                      {item["oai-device-id"] ? `${item["oai-device-id"].slice(0, 13)}…` : "设备 ID 自动生成"}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-8 text-stone-400 hover:text-rose-600"
                      onClick={() => persist(current.filter((_, i) => i !== index))}
                      aria-label="删除条目"
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="rounded-xl border border-dashed border-stone-200 px-4 py-3 text-sm text-stone-500">
                当前使用内置池。添加条目后账号将改为绑定这些条目：共享同一条目的账号会共享设备身份。
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                className="h-10 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                onClick={() => persist([...current, makeRandomEntry(nextSeq)])}
              >
                <Dices className="size-4" />
                随机生成一条
              </Button>
              <div className="flex items-center gap-2">
                <Input
                  value={batchCount}
                  onChange={(event) => setBatchCount(event.target.value.replace(/\D/g, ""))}
                  className="h-10 w-20 rounded-xl border-stone-200 bg-white"
                  aria-label="批量生成数量"
                />
                <Button
                  variant="outline"
                  className="h-10 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                  onClick={() => {
                    const count = Math.min(100, Math.max(1, Number(batchCount) || 1));
                    const add = Array.from({ length: count }, (_, i) => makeRandomEntry(nextSeq + i));
                    persist([...current, ...add]);
                  }}
                >
                  <Dices className="size-4" />
                  批量生成
                </Button>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 rounded-xl bg-stone-50 p-3">
              <Input
                value={manualLabel}
                onChange={(event) => setManualLabel(event.target.value)}
                placeholder="名称（可选）"
                className="h-10 w-36 rounded-xl border-stone-200 bg-white"
              />
              <Select value={manualProfile} onValueChange={setManualProfile}>
                <SelectTrigger className="h-10 w-44 rounded-xl border-stone-200 bg-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROFILE_OPTIONS.map((profile) => (
                    <SelectItem key={profile} value={profile}>
                      {profile}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                className="h-10 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                onClick={() => {
                  persist([
                    ...current,
                    {
                      label: manualLabel.trim() || `手动 ${current.length + 1}`,
                      impersonate: manualProfile,
                    },
                  ]);
                  setManualLabel("");
                }}
              >
                <Plus className="size-4" />
                手动添加
              </Button>
              <p className="w-full text-xs text-stone-400">
                手动添加默认自动生成设备 ID；如需固定设备身份，可在保存后编辑 data 中对应的
                fingerprint_pool JSON。
              </p>
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
