#!/usr/bin/env bash

# U-19 : /etc/hosts 파일 소유자 및 권한 설정
# /etc/hosts 파일의 권한 적절성 여부 점검

set -u

CHECK_ID="U-19"
TARGET_FILE="/etc/hosts"

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
  # /etc/hosts 파일이 없는 경우 (매우 드문 케이스이나 에러 처리)
  state="100"
  content="${TARGET_FILE}_Not_Found"
else
  # 2. 파일 정보 추출
  # %U: 소유자, %a: 8진수 권한 (예: 644)
  read -r F_OWNER F_PERM < <(stat -c "%U %a" "$TARGET_FILE" 2>/dev/null)
  
  IS_VULN=0
  VULN_REASON=""

  # [점검 1] 소유자 확인 (root 여야 함)
  if [ "$F_OWNER" != "root" ]; then
    IS_VULN=1
    VULN_REASON="Owner_is_not_root($F_OWNER)"
  fi

  # [점검 2] 권한 확인 (644 이하 여야 함)
  # 644 이하의 의미: User(rw-), Group(r--), Other(r--)
  # 즉, Group이나 Other 자리에 4(Read)보다 큰 값(Write=2, Execute=1 포함된 5,6,7)이 오면 취약
  
  # 3자리 권한 문자열 추출 (예: 0644 -> 644)
  PERM_STR="${F_PERM: -3}"
  PERM_G="${PERM_STR:1:1}" # Group
  PERM_O="${PERM_STR:2:1}" # Other

  # Group이나 Other가 4보다 크면 (5, 6, 7) 취약
  if [ "$PERM_G" -gt 4 ] || [ "$PERM_O" -gt 4 ]; then
    IS_VULN=1
    if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
    VULN_REASON="${VULN_REASON}Perm_is_greater_than_644($F_PERM)"
  fi

  # 3. 결과 판단
  if [ "$IS_VULN" -eq 1 ]; then
    state="201" # 취약
    # 탭(\t)으로 구분하여 상세 내용 기록
    # 형식: 파일경로 [탭] 취약원인 [탭] 현재설정(소유자:권한)
    content="${TARGET_FILE}\t${VULN_REASON}\tCurrent_Setting(${F_OWNER}:${F_PERM})"
  else
    state="000" # 양호
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