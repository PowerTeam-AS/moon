#!/usr/bin/env bash

# U-18 : /etc/shadow 파일 소유자 및 권한 설정
# /etc/shadow 파일 권한 적절성 여부 점검

set -u

CHECK_ID="U-18"
TARGET_FILE="/etc/shadow"

# ==== 로그 저장 경로 설정 ====
LOG_DIR="/var/log/system_check"
# 날짜
DATE=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="$LOG_DIR/system_check_$(date +%Y%m%d).log"
mkdir -p "$LOG_DIR"

# ==== 점검 걸린 시간 기록
start_ms() {
  if date +%s%3N >/dev/null 2>&1; then
    date +%s%3N
  else
    echo "$(( $(date +%s) * 1000 ))"
  fi
}

now_start="$(start_ms)"

# -------- 진단 로직 --------
state="000" 
content=""  

# 1. 파일 존재 여부 확인
if [ ! -e "$TARGET_FILE" ]; then
  # /etc/shadow가 없는 것은 매우 심각한 오류
  state="100"
  content="${TARGET_FILE}_Not_Found"
else
  # 2. 파일 정보 추출
  # %U: 소유자, %a: 8진수 권한 (예: 400, 600, 000)
  # 2>/dev/null: 권한 부족 시 에러 방지 (root 실행 권장)
  read -r F_OWNER F_PERM < <(stat -c "%U %a" "$TARGET_FILE" 2>/dev/null)
  
  # stat 명령 실패 시 (권한 문제 등)
  if [[ -z "$F_OWNER" ]]; then
    state="100"
    content="Permission_Denied_or_Stat_Failed"
  else
    IS_VULN=0
    VULN_REASON=""

    # [점검 1] 소유자 확인 (root 여야 함)
    if [ "$F_OWNER" != "root" ]; then
      IS_VULN=1
      VULN_REASON="Owner_is_not_root($F_OWNER)"
    fi

    # [점검 2] 권한 확인 (400 이하 여야 함)
    # 가이드 기준: 400 (r--------) 이하. 
    # 즉, 600(rw-------)이나 640(rw-r-----)도 취약으로 간주됨.
    # Bash에서 문자열로 된 숫자를 정수 비교(-gt) 하면 10진수로 계산되나,
    # 8진수 체계에서도 600 > 400 이므로 비교 결과는 동일하게 유효함.
    
    if [ "$F_PERM" -gt 400 ]; then
      IS_VULN=1
      if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
      VULN_REASON="${VULN_REASON}Perm_is_greater_than_400($F_PERM)"
    fi

    # 3. 결과 판단
    if [ "$IS_VULN" -eq 1 ]; then
      state="201" # 취약
      # 형식: 파일경로 [탭] 취약원인 [탭] 현재설정(소유자:권한)
      content="${TARGET_FILE}\t${VULN_REASON}\tCurrent_Setting(${F_OWNER}:${F_PERM})"
    else
      state="000" # 양호
    fi
  fi
fi

now_end="$(start_ms)"
duration_ms=$(( now_end - now_start ))
if (( duration_ms < 0 )); then duration_ms=0; fi

# -------- 로그 작성 --------
{
  echo "check_id ${CHECK_ID}"
  echo "state_code ${CHECK_ID}-${state}"
  echo "check_duration_ms ${duration_ms}"
  if [[ -n "${content}" ]]; then
    # \t 해석을 위해 -e 옵션 사용
    echo -e "content ${content}"
  fi
} > "${LOG_FILE}"