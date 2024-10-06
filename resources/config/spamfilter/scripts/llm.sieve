if eval "LLM_MODEL && LLM_PROMPT_TEXT" {
    let "llm_result" "trim(split_n(llm_prompt(LLM_MODEL, LLM_PROMPT_TEXT + '\n\nSubject: ' + subject_clean + '\n\n' + text_body, 0.5), ',', 3))";

    if eval "eq_ignore_case(llm_result[0], 'Unsolicited')" {
        if eval "eq_ignore_case(llm_result[1], 'High')" {
            let "t.LLM_UNSOLICITED_HIGH" "1";
        } elsif eval "eq_ignore_case(llm_result[1], 'Medium')" {
            let "t.LLM_UNSOLICITED_MEDIUM" "1";
        } else {
            let "t.LLM_UNSOLICITED_LOW" "1";
        }
    } elsif eval "eq_ignore_case(llm_result[0], 'Commercial')" {
        if eval "eq_ignore_case(llm_result[1], 'High')" {
            let "t.LLM_COMMERCIAL_HIGH" "1";
        } elsif eval "eq_ignore_case(llm_result[1], 'Medium')" {
            let "t.LLM_COMMERCIAL_MEDIUM" "1";
        } else {
            let "t.LLM_COMMERCIAL_LOW" "1";
        }
    } elsif eval "eq_ignore_case(llm_result[0], 'Harmful')" {
        if eval "eq_ignore_case(llm_result[1], 'High')" {
            let "t.LLM_HARMFUL_HIGH" "1";
        } elsif eval "eq_ignore_case(llm_result[1], 'Medium')" {
            let "t.LLM_HARMFUL_MEDIUM" "1";
        } else {
            let "t.LLM_HARMFUL_LOW" "1";
        }
    } elsif eval "eq_ignore_case(llm_result[0], 'Legitimate')" {
        if eval "eq_ignore_case(llm_result[1], 'High')" {
            let "t.LLM_LEGITIMATE_HIGH" "1";
        } elsif eval "eq_ignore_case(llm_result[1], 'Medium')" {
            let "t.LLM_LEGITIMATE_MEDIUM" "1";
        } else {
            let "t.LLM_LEGITIMATE_LOW" "1";
        }
    }

    if eval "ADD_HEADER_LLM && count(llm_result) > 2" {
        eval "add_header('X-Spam-Llm-Result', 'Category=' + llm_result[0] + '; Confidence=' + llm_result[1] + '; Explanation=' + llm_result[2])";
    }
}
