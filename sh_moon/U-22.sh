#!/usr/bin/env bash

# U-22 : /etc/services 파일 소유자 및 권한 설정
# /etc/services 파일 권한 적절성 여부 점검

set -u

CHECK_ID="U-22"
TARGET_FILE="/etc/services"

# ==== 로그 저장 경로 설정 ==== # TODO : 루트 변경 시 수정
LOG_DIR="/home/rockylinux/results"
LOG_FILE="$LOG_DIR/$CHECK_ID.log"
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
  # /etc/services 파일이 없는 경우 (네트워크 서비스 포트 정의 파일이므로 보통 존재함)
  state="100"
  content="${TARGET_FILE}_Not_Found"
else
  # 2. 파일 정보 추출
  # %U: 소유자, %a: 8진수 권한 (예: 644)
  read -r F_OWNER F_PERM < <(stat -c "%U %a" "$TARGET_FILE" 2>/dev/null)
  
  # stat 실패 시
  if [[ -z "$F_OWNER" ]]; then
    state="100"
    content="Permission_Denied_or_Stat_Failed"
  else
    IS_VULN=0
    VULN_REASON=""

    # [점검 1] 소유자 확인
    # 가이드 기준: root, bin, sys 허용
    if [[ "$F_OWNER" != "root" && "$F_OWNER" != "bin" && "$F_OWNER" != "sys" ]]; then
      IS_VULN=1
      VULN_REASON="Owner_invalid($F_OWNER)"
    fi

    # [점검 2] 권한 확인 (644 이하 여야 함)
    # 644 의미: User(rw-), Group(r--), Other(r--)
    # 즉, Group이나 Other에 Write(2)나 Execute(1)가 있으면 취약 (4보다 큰 값)
    
    PERM_STR="${F_PERM: -3}"
    PERM_G="${PERM_STR:1:1}" # Group
    PERM_O="${PERM_STR:2:1}" # Other

    # Group 권한이 4(Read)보다 크면 취약
    if [[ "$PERM_G" -gt 4 ]]; then
      IS_VULN=1
      if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
      VULN_REASON="${VULN_REASON}Group_Perm_High($F_PERM)"
    fi

    # Other 권한이 4(Read)보다 크면 취약
    if [[ "$PERM_O" -gt 4 ]]; then
      IS_VULN=1
      if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
      VULN_REASON="${VULN_REASON}Other_Perm_High($F_PERM)"
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