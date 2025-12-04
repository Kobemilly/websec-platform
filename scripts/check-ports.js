#!/usr/bin/env node
/**
 * Port 衝突檢查工具
 * 遵循 SKILL_SEC.prompt.md - Pre-Execution Safety 標準
 * 
 * 檢查以下 Port 是否被占用:
 * - 8085 (Backend API)
 * - 3005 (Frontend)
 * - 8081 (Scanner - 如果使用 API 模式)
 */

const { execSync } = require('child_process');
const readline = require('readline');

const PORTS_TO_CHECK = [
  { port: 8085, service: 'Backend API' },
  { port: 3005, service: 'Frontend' }
];

const COLORS = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

function checkPort(port) {
  try {
    // 使用 lsof 檢查 Port (Linux/macOS)
    const output = execSync(`lsof -i :${port} -t`, { encoding: 'utf8' }).trim();
    if (output) {
      const pid = output.split('\n')[0];
      try {
        const processInfo = execSync(`ps -p ${pid} -o comm=`, { encoding: 'utf8' }).trim();
        return { occupied: true, pid, process: processInfo };
      } catch {
        return { occupied: true, pid, process: 'Unknown' };
      }
    }
    return { occupied: false };
  } catch (error) {
    // lsof 返回非零退出碼表示 Port 未被占用
    return { occupied: false };
  }
}

function killProcess(pid) {
  try {
    execSync(`kill -9 ${pid}`, { stdio: 'inherit' });
    return true;
  } catch (error) {
    console.error(`${COLORS.red}✗ 無法終止 PID ${pid}${COLORS.reset}`);
    return false;
  }
}

async function askUser(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.toLowerCase());
    });
  });
}

async function main() {
  console.log(`\n${COLORS.blue}${COLORS.bold}🛡️  Port 衝突檢查工具${COLORS.reset}`);
  console.log(`${COLORS.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLORS.reset}\n`);

  const conflicts = [];

  // 檢查所有 Port
  for (const { port, service } of PORTS_TO_CHECK) {
    const result = checkPort(port);
    if (result.occupied) {
      conflicts.push({ port, service, ...result });
      console.log(`${COLORS.yellow}⚠️  Port ${port} (${service}) 被占用${COLORS.reset}`);
      console.log(`   PID: ${result.pid}`);
      console.log(`   Process: ${result.process}\n`);
    } else {
      console.log(`${COLORS.green}✓ Port ${port} (${service}) 可用${COLORS.reset}`);
    }
  }

  // 如果有衝突,詢問使用者
  if (conflicts.length > 0) {
    console.log(`\n${COLORS.red}${COLORS.bold}發現 ${conflicts.length} 個 Port 衝突${COLORS.reset}\n`);
    
    const answer = await askUser(
      `${COLORS.yellow}是否要終止這些 Process? (y/n): ${COLORS.reset}`
    );

    if (answer === 'y' || answer === 'yes') {
      console.log();
      for (const conflict of conflicts) {
        process.stdout.write(`正在終止 PID ${conflict.pid} (Port ${conflict.port})... `);
        if (killProcess(conflict.pid)) {
          console.log(`${COLORS.green}✓${COLORS.reset}`);
        }
      }
      console.log(`\n${COLORS.green}${COLORS.bold}✓ 所有衝突已解決${COLORS.reset}\n`);
    } else {
      console.log(`\n${COLORS.red}✗ 使用者取消操作${COLORS.reset}`);
      console.log(`${COLORS.yellow}請手動處理 Port 衝突後再啟動服務${COLORS.reset}\n`);
      process.exit(1);
    }
  } else {
    console.log(`\n${COLORS.green}${COLORS.bold}✓ 所有 Port 檢查通過${COLORS.reset}\n`);
  }
}

main().catch((error) => {
  console.error(`${COLORS.red}錯誤: ${error.message}${COLORS.reset}`);
  process.exit(1);
});
