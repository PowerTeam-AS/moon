#!/usr/bin/env bash

# U-15 : 파일 및 디렉터리 소유자 설정
# 소유자가 존재하지 않는 파일 및 디렉토리 존재 여부 점검

set -u

CHECK_ID="U-15"

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

# 1. 점검 명령어 실행
# -xdev : 다른 파일 시스템(파티션)으로 넘어가지 않음 (성능 및 루프 방지)
# -nouser : 소유자가 없는 파일 (UID는 있지만 /etc/passwd에 없는 경우)
# -nogroup : 그룹이 없는 파일 (GID는 있지만 /etc/group에 없는 경우)
# 2>/dev/null : 권한 거부 에러 등은 무시

# 대량의 파일이 나올 수 있으므로 임시 파일에 저장
TMP_LIST=$(mktemp)

# 시스템 전체 스캔 (시간이 다소 소요됨)
find / -xdev \( -nouser -o -nogroup \) -print > "$TMP_LIST" 2>/dev/null

# 2. 결과 판단
if [ -s "$TMP_LIST" ]; then
  # 파일이 하나라도 존재하면 취약
  state="201"
  
  # 발견된 파일 개수 확인
  VULN_COUNT=$(wc -l < "$TMP_LIST")
  
  # content 필드 작성
  # 결과가 너무 많을 수 있으므로 상위 5개만 샘플로 기록하고 전체 개수 명시
  # 탭(\t) 구분자로 나열
  TOP_FILES=$(head -n 5 "$TMP_LIST" | tr '\n' '\t')
  
  # 마지막 탭 문자 제거 및 포맷팅
  # 예: content /tmp/orphan1 \t /home/user/del_file \t ... (Total: 12)
  content="${TOP_FILES}...(Total_Found:${VULN_COUNT})"
else
  # 양호
  state="000"
fi

# 임시 파일 삭제
rm -f "$TMP_LIST"

now_end="$(start_ms)"
duration_ms=$(( now_end - now_start ))
if (( duration_ms < 0 )); then duration_ms=0; fi

# -------- 로그 작성 --------
{
  echo "check_id ${CHECK_ID}"
  echo "state_code ${CHECK_ID}-${state}"
  echo "check_duration_ms ${duration_ms}"
  if [[ -n "${content}" ]]; then
    # \t 등을 해석하기 위해 -e 옵션 사용
    echo -e "content ${content}"
  fi
} > "${LOG_FILE}"