#!/usr/bin/env bash

# U-17 : 시스템 시작 스크립트 권한 설정
# 시스템 시작 스크립트 파일 권한 적절성 여부 점검
# 점검 내용: 시스템 시작 스크립트(/etc/rc.d/*)의 소유자가 root이고, Other에게 쓰기 권한이 없는지 점검

set -u

CHECK_ID="U-17"
TARGET_DIR="/etc/rc.d"

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

# 권한 문자열(3자리 또는 4자리)에서 Group 또는 Other에 Write(2) 권한이 있는지 확인
# 리턴: 0(취약-쓰기권한있음), 1(양호-쓰기권한없음)
has_group_or_other_write() {
  local perm="$1"
  [[ "$perm" =~ ^[0-7]{3,4}$ ]] || return 0

  # 뒤에서 3자리만 추출 (예: 0755 -> 755)
  perm="${perm: -3}"
  local g="${perm:1:1}" # Group
  local o="${perm:2:1}" # Other

  # Write 비트(2)가 포함된 권한: 2(w-), 3(wx), 6(rw-), 7(rwx)
  case "$g" in 2|3|6|7) return 0;; esac
  case "$o" in 2|3|6|7) return 0;; esac
  
  return 1
}

# -------- 진단 로직 --------
state="000"   # 초기 상태: 양호
content=""    # 조치 필요 내용

# 1. 점검 대상 디렉터리 존재 확인
if [ ! -d "$TARGET_DIR" ]; then
  # Rocky Linux 등에서는 /etc/rc.d가 존재함. 없으면 점검 불가(N/A) 혹은 양호 처리
  # 여기서는 파일이 없으므로 양호로 처리하되 로그 남김
  # (시스템에 따라 /etc/init.d 만 있을 수도 있음)
  if [ -d "/etc/init.d" ]; then
    TARGET_DIR="/etc/init.d"
  else
    # 대상이 아예 없으면 양호로 간주하고 종료
    state="000"
    content="Target_Directory_Not_Found(Skipped)"
  fi
fi

# 2. 파일 점검 루프
# 대상 디렉터리가 존재하고 스킵되지 않은 경우 실행
if [[ "$content" != *"Skipped"* ]]; then
  
  # find 명령어로 파일(-type f)만 검색
  # 시작 스크립트는 보통 실행 파일이므로 실행 권한이 있을 수 있음 -> Write 권한만 체크
  FOUND_VULN=0
  
  while IFS= read -r file; do
    # 파일 정보 추출
    read -r F_OWNER F_PERM < <(stat -c "%U %a" "$file" 2>/dev/null)
    
    IS_VULN=0
    VULN_REASON=""

    # [점검 1] 소유자 root 확인
    if [ "$F_OWNER" != "root" ]; then
      IS_VULN=1
      VULN_REASON="Owner_is_not_root($F_OWNER)"
    fi

    # [점검 2] 권한 확인 (Group/Other Write 권한 없어야 함)
    # 가이드 조치사례: chmod o-w (Other Write 제거)
    # 보안 강화를 위해 Group Write도 함께 체크
    if ! has_group_or_other_write "$F_PERM"; then
      IS_VULN=1
      if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
      VULN_REASON="${VULN_REASON}Perm_has_Write($F_PERM)"
    fi

    # 취약점 발견 시 기록
    if [ "$IS_VULN" -eq 1 ]; then
      FOUND_VULN=1
      # 상태 코드 변경 (최초 1회)
      if [ "$state" == "000" ]; then state="201"; fi
      
      # content 누적 (탭 구분)
      if [[ -n "$content" ]]; then content="${content}\t"; fi
      content="${content}${file}(${VULN_REASON})"
      
      # 너무 많은 파일이 걸릴 경우 로그 폭주 방지 (선택 사항: 10개까지만 기록 등)
      # 여기서는 요구사항에 맞춰 계속 기록
    fi
    
  done < <(find "$TARGET_DIR" -type f 2>/dev/null)
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