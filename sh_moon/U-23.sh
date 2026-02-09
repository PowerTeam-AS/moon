#!/usr/bin/env bash

# U-23 : SUID, SGID, Sticky bit 설정 파일 점검
# 불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검

set -u

CHECK_ID="U-23"
# 타겟 아래에 작성 (여러 파일)

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

# 임시 파일 생성
TMP_LIST=$(mktemp)

# 1. SUID/SGID 파일 검색
# 가이드 기준: root 소유(-user root), 파일(-type f), SUID(-perm -04000) 또는 SGID(-perm -02000)
# -xdev : 다른 파티션 검색 제외 (성능 최적화 및 루프 방지)
find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -print 2>/dev/null > "$TMP_LIST"

# 2. 결과 분석
if [ -s "$TMP_LIST" ]; then
  # SUID/SGID 파일이 발견된 경우
  # 시스템에는 기본적으로 필요한 SUID 파일(passwd, sudo 등)이 있으므로
  # 발견되었다고 무조건 '취약'은 아니지만, 점검 목록을 제공하여 관리자가 판단하도록 함.
  
  # 상태 코드는 '검토 필요' 또는 '취약 가능성' 의미로 201 사용 (혹은 정책에 따라 100 등 사용)
  state="201"
  
  # 파일 개수 확인
  COUNT=$(wc -l < "$TMP_LIST")
  
  # 상위 10개 파일만 샘플로 content에 기록 (전체 목록은 별도 파일 확인 필요할 수 있음)
  # 탭(\t)으로 구분하여 가독성 확보
  TOP_FILES=$(head -n 10 "$TMP_LIST" | tr '\n' '\t')
  
  # content 작성
  content="Total_Found:${COUNT}\tCheck_List:${TOP_FILES}..."
else
  # 발견되지 않은 경우 (매우 드문 케이스)
  state="000"
  content="No_SUID/SGID_Files_Found"
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
    # \t 해석을 위해 -e 옵션 사용
    echo -e "content ${content}"
  fi
} > "${LOG_FILE}"