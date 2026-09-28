"use client";

import { useEffect, useState } from "react";
import { BadgeCheck, Dices, LoaderCircle, Plus, Save, ShieldCheck, Trash2, Waves } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { verifyImpersonate, type ImpersonateVerifyResult } from "@/lib/api";

import { useSettingsStore } from "../store";

// 与后端 fingerprintPool 对齐:实测可通过 Cloudflare 的变体
const PROFILE_OPTIONS = [
  "firefox",
  "mac-firefox",
  "linux-firefox",
  "android-firefox",
  "ios-firefox",
  "chrome103",
  "chrome110",
  "chrome111",
  "chrome112",
  "chrome117",
  "opera91",
];

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

  const [verifying, setVerifying] = useState<Record<string, boolean>>({});
  const [verifyResults, setVerifyResults] = useState<Record<string, ImpersonateVerifyResult | null>>({});

  const config = useSettingsStore((state) => state.config);
  const isLoadingConfig = useSettingsStore((state) => state.isLoadingConfig);
  const isSavingConfig = useSettingsStore((state) => state.isSavingConfig);
  const setFingerprintPool = useSettingsStore((state) => state.setFingerprintPool);
  const setProxyIdentityEnabled = useSettingsStore((state) => state.setProxyIdentityEnabled);
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
    // 条目增删后行号变化,清空旧验证结果避免显示错位
    setVerifyResults({});
    setFingerprintPool(next.length > 0 ? JSON.stringify(next) : "");
  };

  // 添加条目并自动逐条验证新增部分
  const addEntries = (list: PoolEntry[]) => {
    const start = current.length;
    persist([...current, ...list]);
    void runVerifyAll(list.map((item, i) => ({ key: `entry-${start + i}`, profile: item.impersonate })));
  };

  const handleSave = async () => {
    await saveConfig();
  };

  const runVerify = async (key: string, profile: string) => {
    setVerifying((prev) => ({ ...prev, [key]: true }));
    setVerifyResults((prev) => ({ ...prev, [key]: null }));
    try {
      const data = await verifyImpersonate(profile);
      setVerifyResults((prev) => ({ ...prev, [key]: data.result }));
    } catch (error) {
      setVerifyResults((prev) => ({
        ...prev,
        [key]: { ok: false, status: 0, latency_ms: 0, error: error instanceof Error ? error.message : "验证失败" },
      }));
    } finally {
      setVerifying((prev) => ({ ...prev, [key]: false }));
    }
  };

  const runVerifyAll = async (items: Array<{ key: string; profile: string }>) => {
    for (const item of items) {
      await runVerify(item.key, item.profile);
    }
  };

  const verifyChip = (key: string) => {
    if (verifying[key]) {
      return <LoaderCircle className="size-4 animate-spin text-stone-400" />;
    }
    const result = verifyResults[key];
    if (!result) {
      return null;
    }
    return result.ok ? (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700">
        <BadgeCheck className="size-4" />
        通过 {result.status} · {result.latency_ms}ms
      </span>
    ) : (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-rose-700">
        <ShieldCheck className="size-4" />
        {result.error ? String(result.error) : `HTTP ${result.status}`}
      </span>
    );
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
                账号按哈希绑定池中条目，7 天粘性，命中挑战自动换下一个。留空时系统自动生成
                20 个内置身份（5 个实测变体 × 独立设备身份，每部署唯一）并在首次使用时持久化。
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
                    {verifyChip(`entry-${index}`)}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 rounded-lg px-2 text-xs text-stone-500 hover:text-stone-800"
                      onClick={() => void runVerify(`entry-${index}`, item.impersonate)}
                      disabled={verifying[`entry-${index}`]}
                    >
                      验证
                    </Button>
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
                当前使用自动生成的 20 个内置身份。添加自定义条目后账号将改为绑定这些条目：共享同一条目的账号会共享设备身份。
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              {current.length > 0 ? (
                <Button
                  variant="outline"
                  className="h-10 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                  onClick={() =>
                    void runVerifyAll(
                      current.map((item, index) => ({ key: `entry-${index}`, profile: item.impersonate })),
                    )
                  }
                  disabled={Object.values(verifying).some(Boolean)}
                >
                  <ShieldCheck className="size-4" />
                  验证全部条目
                </Button>
              ) : null}
              <Button
                variant="outline"
                className="h-10 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                onClick={() => addEntries([makeRandomEntry(nextSeq)])}
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
                    addEntries(add);
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
                  addEntries([
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

            <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-stone-200 bg-white p-4">
              <Checkbox
                id="settings-proxy-identity"
                checked={config?.proxy_identity_enabled === true}
                onCheckedChange={(checked) => setProxyIdentityEnabled(checked === true)}
                className="mt-0.5"
              />
              <span className="space-y-1">
                <span className="block text-sm font-medium text-stone-700">账号独立代理身份（Resin 粘性池）</span>
                <span className="block text-xs leading-5 text-stone-500">
                  开启后，访问上游时代理用户名会按账号指纹自动改写为
                  「用户名.账号标识」，适配 Resin 类粘性池的
                  「平台.账号:令牌」格式——每个 GPT 账号绑定独立且稳定的出口
                  IP，指纹轮换时出口 IP 同步更换。普通账号密码代理请勿开启。
                </span>
              </span>
            </label>

            <div className="space-y-2 rounded-xl border border-stone-200 p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-stone-700">实测变体可用性</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 rounded-lg px-2 text-xs text-stone-500 hover:text-stone-800"
                  onClick={() =>
                    void runVerifyAll(PROFILE_OPTIONS.map((profile) => ({ key: `builtin-${profile}`, profile })))
                  }
                  disabled={Object.values(verifying).some(Boolean)}
                >
                  全部验证
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                {PROFILE_OPTIONS.map((profile) => (
                  <span
                    key={profile}
                    className="inline-flex items-center gap-2 rounded-lg border border-stone-200 bg-white px-2.5 py-1.5 text-xs"
                  >
                    <span className="font-mono text-stone-600">{profile}</span>
                    {verifyChip(`builtin-${profile}`)}
                    <button
                      type="button"
                      className="text-stone-400 hover:text-stone-700"
                      onClick={() => void runVerify(`builtin-${profile}`, profile)}
                      disabled={verifying[`builtin-${profile}`]}
                    >
                      验证
                    </button>
                  </span>
                ))}
              </div>
              <p className="text-xs text-stone-400">
                验证走当前全局代理请求 chatgpt.com 首页，返回 200 表示该指纹当前可通过 Cloudflare；随机/批量/手动添加的条目会自动逐条验证并在列表中显示结果。
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
