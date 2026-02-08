#!/usr/bin/env bash

# U-14 : root 홈, 패스 디렉터리 권한 및 패스 설정
# root 계정의 PATH 환경변수에 "."이 포함 여부 점검
# Fields : check_id, state_code, check_duration_ms, content(취약 대상 목록)

# TODO set -u : 정의되지 않은 변수를 참조할 경우 에러 발생시키고 종료 
# TODO mkdir -p : 상위 디렉토리가 없을 경우 상위 디렉토리도 함께 생성

set -u

CHECK_ID="U-14"

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

# --- 진단 로직 ----
state="000"
content=""

# 1. root 권한 확인 (PATH 점검은 root의 환경변수가 중요)
if [ "$EUID" -ne 0 ]; then
  # root가 아닌 경우에 정확한 점검이 불가
  state="100"
  # content="현재 사용자가 root가 아님"
else
  # PATH 변수 점검
  CURRENT_PATH="$PATH"
  IS_VULN=0
  VULN_DETAIL=""

  # CASE 1 : 맨 앞에 .
  if [[ "$CURRENT_PATH" =~ ^\.:? ]]; then
    IS_VULN=1
    VULN_DETAIL+="PATH 맨 앞에 '.' 포함. "
  fi
  
  # 케이스 2: 중간에 점(.)이 있는 경우
  if [[ "$CURRENT_PATH" =~ :\.: ]]; then
    IS_VULN=1
    if [[ -n "$VULN_DETAIL" ]]; then VULN_DETAIL="${VULN_DETAIL}, "; fi
    VULN_DETAIL="${VULN_DETAIL}PATH_contains_dot_in_middle"
  fi

  # 케이스 3: 빈 경로(::)가 포함된 경우 (리눅스에서 ::는 .과 같음)
  if [[ "$CURRENT_PATH" =~ :: ]]; then
    IS_VULN=1
    if [[ -n "$VULN_DETAIL" ]]; then VULN_DETAIL="${VULN_DETAIL}, "; fi
    VULN_DETAIL="${VULN_DETAIL}PATH_contains_empty_entry(::)"
  fi

  # 3. 결과 판단
  if [[ "$IS_VULN" -eq 1 ]]; then
    # 취약 (200번대 코드 사용)
    state="201"
    # 탭(\t)으로 구분하여 가독성 확보 (요청하신 포맷)
    content="env:PATH\t${VULN_DETAIL}\tCurrent_PATH:[${CURRENT_PATH}]"
  else
    # 양호
    state="000"
  fi
fi

new_end="$(start_ms)"
duration_ms=$((new_end - now_start))
if ((duration_ms < 0)); then
  duration_ms=0
fi

# ------ 로그 작성 ------- 
{
  echo "check_id ${CHECK_ID}"
  echo "state_code ${CHECK_ID}-${state}"
  echo "check_duration_ms ${duration_ms}"
  if [[ -n "${content}" ]]; then
    # content가 있을 때만 출력 (양호일 때는 보통 생략하거나, "None" 등으로 합의 필요 시 수정)
    echo -e "content ${content}"
  fi
} > "${LOG_FILE}"