#!/usr/bin/env bash

# U-21 : /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# /etc/(r)syslog.conf 파일 권한 적절성 여부 점검

set -u

CHECK_ID="U-21"
# 타겟 아래에 작성 (여러 파일)

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

CHECK_TARGETS=(
  "/etc/syslog.conf"
  "/etc/rsyslog.conf"
)

FOUND_VULN=0

# 2. 파일 점검 루프
for TARGET_FILE in "${CHECK_TARGETS[@]}"; do
  # 파일이 존재하지 않으면 건너뜀 (둘 중 하나만 있어도 점검 수행)
  if [ ! -e "$TARGET_FILE" ]; then
    continue
  fi

  # 파일 정보 추출 (%U: 소유자, %a: 8진수 권한)
  read -r F_OWNER F_PERM < <(stat -c "%U %a" "$TARGET_FILE" 2>/dev/null)

  # stat 실패 시 건너뜀
  [[ -z "$F_OWNER" ]] && continue

  IS_VULN=0
  VULN_REASON=""

  # [점검 1] 소유자 확인
  # 가이드 기준: root, bin, sys 허용
  if [[ "$F_OWNER" != "root" && "$F_OWNER" != "bin" && "$F_OWNER" != "sys" ]]; then
    IS_VULN=1
    VULN_REASON="Owner_invalid($F_OWNER)"
  fi

  # [점검 2] 권한 확인 (640 이하 여야 함)
  # 640 이하의 의미: 
  # - User: rw(6) 이하
  # - Group: r(4) 이하 (즉, 0 또는 4만 허용. 1,2,3,5,6,7은 취약)
  # - Other: 0 (권한 없음)이어야 함
  
  PERM_STR="${F_PERM: -3}"
  PERM_G="${PERM_STR:1:1}" # Group
  PERM_O="${PERM_STR:2:1}" # Other

  # Group 점검: 0(권한없음) 또는 4(읽기)가 아니면 취약 (Write(2)나 Exec(1) 포함 시 취약)
  if [[ "$PERM_G" -ne 0 && "$PERM_G" -ne 4 ]]; then
    IS_VULN=1
    if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
    VULN_REASON="${VULN_REASON}Group_Perm_High($F_PERM)"
  fi

  # Other 점검: 0이 아니면 취약
  if [[ "$PERM_O" -ne 0 ]]; then
    IS_VULN=1
    if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
    VULN_REASON="${VULN_REASON}Other_Perm_High($F_PERM)"
  fi

  # 취약점 발견 시 기록
  if [ "$IS_VULN" -eq 1 ]; then
    FOUND_VULN=1
    
    # 상세 내용 누적 (탭 구분)
    if [[ -n "$content" ]]; then content="${content}\t"; fi
    content="${content}${TARGET_FILE}(${VULN_REASON})"
  fi
done

# 3. 최종 결과 상태 판단
if [ "$FOUND_VULN" -eq 1 ]; then
  state="201" # 취약
else
  # 파일은 없지만 로직상 양호로 처리하거나, 파일이 하나도 없는 경우 별도 처리
  # 여기서는 발견된 취약점이 없으면 양호로 간주
  state="000"
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
    echo -e "content ${content}"
  fi
} > "${LOG_FILE}"